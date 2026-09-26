package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{header: make(http.Header)}
}

func (w *captureWriter) Header() http.Header    { return w.header }
func (w *captureWriter) WriteHeader(status int) { w.status = status }
func (w *captureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func testDNSResponse() []byte {
	return []byte{
		0x00, 0x01, // transaction ID used by the test DoH requests
		0x81, 0x80, // response, no error
		0x00, 0x01, 0x00, 0x01, // one question and one answer
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01, // A, IN
		0xc0, 0x0c, // compressed owner name -> example.com
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c, // TTL 300
		0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
	}
}

// stateCount is a test-only view of the total tracked source states.
func (t *sourceTable) stateCount() int {
	n := 0
	for i := 0; i < t.shardCount; i++ {
		s := &t.shards[i]
		s.mu.Lock()
		n += len(s.clients)
		s.mu.Unlock()
	}
	return n
}

func TestSourceTableIsBounded(t *testing.T) {
	table := newSourceTable(128)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		key := "192.0.2." + strconv.Itoa(i%250)
		_ = table.admitRequest(key, 2, now.Add(time.Duration(i)*time.Millisecond))
		table.releaseRequest(key)
	}
	if got := table.stateCount(); got > 128 {
		t.Fatalf("state table exceeded bound: got %d", got)
	}
}

func TestDefaultResourceProfile(t *testing.T) {
	cfg := defaultGuardConfig()
	if cfg.MaxGlobalConns != 256 {
		t.Fatalf("global connections = %d, want 256", cfg.MaxGlobalConns)
	}
	if cfg.MaxPerIPConns != 64 {
		t.Fatalf("per-IP connections = %d, want 64", cfg.MaxPerIPConns)
	}
	if cfg.MaxDNSMessage != 4096 {
		t.Fatalf("DoH body size = %d, want 4096", cfg.MaxDNSMessage)
	}
	if cfg.MaxUpstreamConns != 8 {
		t.Fatalf("upstream connections = %d, want 8", cfg.MaxUpstreamConns)
	}
	if cfg.MaxConcurrentReqs != 16 || cfg.MaxConcurrentReqsPerIP != 8 {
		t.Fatalf("request concurrency = %d/%d, want 16/8", cfg.MaxConcurrentReqs, cfg.MaxConcurrentReqsPerIP)
	}
	if cfg.MaxSourceStates != 512 {
		t.Fatalf("source states = %d, want 512", cfg.MaxSourceStates)
	}
	if cfg.BackendTimeout != 8*time.Second {
		t.Fatalf("guard response timeout = %s, want 8s", cfg.BackendTimeout)
	}
}

func TestResourceEnvironmentOverrides(t *testing.T) {
	t.Setenv("GLOBAL_CONN_LIMIT", "33")
	t.Setenv("IP_CONN_LIMIT", "34")
	t.Setenv("DOH_MAX_BODY_BYTES", "2048")
	t.Setenv("UPSTREAM_MAX_CONNS", "5")
	t.Setenv("GUARD_MAX_CONCURRENT_REQS", "10")
	t.Setenv("GUARD_MAX_CONCURRENT_REQS_PER_IP", "9")
	t.Setenv("GUARD_RESPONSE_TIMEOUT", "7")

	cfg := loadGuardConfig()
	if cfg.MaxGlobalConns != 33 || cfg.MaxPerIPConns != 34 || cfg.MaxDNSMessage != 2048 || cfg.MaxUpstreamConns != 5 || cfg.MaxConcurrentReqs != 10 || cfg.MaxConcurrentReqsPerIP != 9 {
		t.Fatalf("resource env override mismatch: global=%d ip=%d body=%d upstream=%d global-req=%d per-ip-req=%d", cfg.MaxGlobalConns, cfg.MaxPerIPConns, cfg.MaxDNSMessage, cfg.MaxUpstreamConns, cfg.MaxConcurrentReqs, cfg.MaxConcurrentReqsPerIP)
	}
	if cfg.BackendTimeout != 7*time.Second {
		t.Fatalf("response timeout = %s, want 7s", cfg.BackendTimeout)
	}
}

func TestLegacyGuardEnvironmentNamesStillWork(t *testing.T) {
	t.Setenv("GUARD_MAX_GLOBAL_CONNS", "44")
	t.Setenv("GUARD_MAX_DNS_MESSAGE", "3072")
	cfg := loadGuardConfig()
	if cfg.MaxGlobalConns != 44 || cfg.MaxDNSMessage != 3072 {
		t.Fatalf("legacy env aliases failed: global=%d body=%d", cfg.MaxGlobalConns, cfg.MaxDNSMessage)
	}
}

func TestPerIPConnectionLimit64(t *testing.T) {
	table := newSourceTable(128)
	now := time.Now()
	key := "203.0.113.9"
	for i := 0; i < 64; i++ {
		if !table.admitConn(key, 64, now) {
			t.Fatalf("connection %d rejected below the 64-connection per-IP limit", i+1)
		}
	}
	if table.admitConn(key, 64, now) {
		t.Fatal("65th connection should be rejected")
	}
	for i := 0; i < 64; i++ {
		table.releaseConn(key)
	}
	if !table.admitConn(key, 64, now) {
		t.Fatal("connection should be admitted after release")
	}
	table.releaseConn(key)
}

func TestSourceKeyCanonicalizesIPv4MappedIPv6(t *testing.T) {
	if got := canonicalIPKey(net.ParseIP("::ffff:192.0.2.44")); got != "192.0.2.44" {
		t.Fatalf("unexpected source key: %q", got)
	}
}

func TestTrackedConnCloseReleasesCounters(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	server, client := net.Pipe()
	defer client.Close()
	ok := g.states.admitConn("192.0.2.55", g.cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("connection admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	tracked := &trackedConn{Conn: server, guard: g, source: "192.0.2.55"}
	if got := g.globalCon.Load(); got != 1 {
		t.Fatalf("global count before close = %d", got)
	}
	_ = tracked.Close()
	if got := g.globalCon.Load(); got != 0 {
		t.Fatalf("global count after close = %d", got)
	}
}

func TestReadDoHBodyEnforcesWireSizeBeforeForwarding(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxDNSMessage = 64
	g := NewGuard(cfg)
	valid := bytes.Repeat([]byte{0x42}, 64)
	req, err := http.NewRequest(http.MethodPost, "http://guard/dns-query", bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	body, err := g.readDoHBody(req)
	if err != nil || !bytes.Equal(body, valid) {
		t.Fatalf("valid body rejected: len=%d err=%v", len(body), err)
	}

	over := bytes.Repeat([]byte{0x43}, 65)
	req, err = http.NewRequest(http.MethodPost, "http://guard/dns-query", bytes.NewReader(over))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	if _, err := g.readDoHBody(req); err == nil {
		t.Fatal("oversized body was accepted")
	}
}

func TestReadDoHGetRejectsOversizedDecodedMessage(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxDNSMessage = 64
	g := NewGuard(cfg)
	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.readDoHBody(req); err == nil {
		t.Fatal("oversized GET message was accepted")
	}
}

func TestTrackedConnQueryCap(t *testing.T) {
	c := &trackedConn{}
	if !c.nextQuery(2) || !c.nextQuery(2) {
		t.Fatal("query cap rejected within limit")
	}
	if c.nextQuery(2) {
		t.Fatal("query cap allowed query over limit")
	}
}

func TestSourceTablePerClientConcurrencyIsBounded(t *testing.T) {
	table := newSourceTable(64)
	now := time.Now()
	key := "203.0.113.10"
	if !table.admitRequest(key, 2, now) || !table.admitRequest(key, 2, now) {
		t.Fatal("request concurrency admission failed within limit")
	}
	if table.admitRequest(key, 2, now) {
		t.Fatal("per-client concurrency limit was bypassed")
	}
	table.releaseRequest(key)
	if !table.admitRequest(key, 2, now) {
		t.Fatal("request slot was not released")
	}
}

func TestSourceTableFailedRequestAdmissionDoesNotReleaseActiveSlot(t *testing.T) {
	table := newSourceTable(64)
	now := time.Now()
	key := "203.0.113.11"
	if !table.admitRequest(key, 2, now) || !table.admitRequest(key, 2, now) {
		t.Fatal("request concurrency admission failed within limit")
	}
	if table.admitRequest(key, 2, now) {
		t.Fatal("third request should be rejected")
	}
	shard := table.shard(key)
	shard.mu.Lock()
	got := shard.clients[key].requests
	shard.mu.Unlock()
	if got != 2 {
		t.Fatalf("failed admission changed active request count: got %d, want 2", got)
	}
}

func TestGlobalRequestConcurrencyIsBounded(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	g.cfg.MaxConcurrentReqs = 2
	if !g.acquireRequest() || !g.acquireRequest() {
		t.Fatal("request concurrency admission failed within limit")
	}
	if g.acquireRequest() {
		t.Fatal("third request should be rejected at aggregate limit")
	}
	g.releaseGlobalRequest()
	if !g.acquireRequest() {
		t.Fatal("aggregate request slot was not released")
	}
	g.releaseGlobalRequest()
	g.releaseGlobalRequest()
}

func TestTrustedProxyRejectsMissingOrInvalidClientIdentity(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	state := &trackedConn{source: "10.0.0.2", trusted: true, guard: g}

	for _, header := range []string{"", "not-an-ip", "198.51.100.8, 10.0.0.2"} {
		req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
		if err != nil {
			t.Fatal(err)
		}
		if header != "" {
			req.Header.Set("X-Forwarded-For", header)
		}
		req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, state))
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("header %q produced status %d, want 400", header, w.Code)
		}
	}
}

func TestNormalizeSourceStateCapFollowsGlobalConnections(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxGlobalConns = 100
	cfg.MaxSourceStates = 1000
	cfg.normalize()
	if cfg.MaxSourceStates != 200 {
		t.Fatalf("source state cap = %d, want 200", cfg.MaxSourceStates)
	}

	cfg.MaxGlobalConns = 40000
	cfg.MaxSourceStates = 65535
	cfg.normalize()
	if cfg.MaxSourceStates != 65535 {
		t.Fatalf("hard source state cap = %d, want 65535", cfg.MaxSourceStates)
	}
}

func TestSourceTableConcurrent64ConnectionsFromOneIP(t *testing.T) {
	table := newSourceTable(512)
	const limit = 64
	const key = "203.0.113.64"
	start := make(chan struct{})
	var wg sync.WaitGroup
	var admitted atomic.Int32
	wg.Add(limit)
	for i := 0; i < limit; i++ {
		go func() {
			defer wg.Done()
			<-start
			if table.admitConn(key, limit, time.Now()) {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != limit {
		t.Fatalf("concurrent admissions = %d, want %d", got, limit)
	}
	if table.admitConn(key, limit, time.Now()) {
		t.Fatal("65th concurrent connection should be rejected")
	}
	for i := 0; i < limit; i++ {
		table.releaseConn(key)
	}
}

func TestSourceTableConcurrent128ConnectionsAcrossIPs(t *testing.T) {
	table := newSourceTable(512)
	const count = 128
	start := make(chan struct{})
	var wg sync.WaitGroup
	var admitted atomic.Int32
	wg.Add(count)
	for i := 0; i < count; i++ {
		key := "198.51.100." + strconv.Itoa(i%250)
		go func(key string) {
			defer wg.Done()
			<-start
			if table.admitConn(key, 64, time.Now()) {
				admitted.Add(1)
			}
		}(key)
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != count {
		t.Fatalf("concurrent multi-IP admissions = %d, want %d", got, count)
	}
	for i := 0; i < count; i++ {
		key := "198.51.100." + strconv.Itoa(i%250)
		table.releaseConn(key)
	}
}

func TestBackendPoolUsesConfiguredConnectionCeiling(t *testing.T) {
	cfg := defaultGuardConfig()
	g := NewGuard(cfg)
	tr, ok := g.backend.Transport.(*http.Transport)
	if !ok {
		t.Fatal("backend transport is not *http.Transport")
	}
	if tr.MaxConnsPerHost != 8 || tr.MaxIdleConns != 8 || tr.MaxIdleConnsPerHost != 8 {
		t.Fatalf("backend pool = max=%d idle=%d idle-host=%d, want 8/8/8", tr.MaxConnsPerHost, tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
}

func TestNormalizeCapsRequestConcurrencyToPlatformInt(t *testing.T) {
	maxPlatformInt := int64(^uint(0) >> 1)
	if maxPlatformInt < int64(^uint32(0)) {
		cfg := defaultGuardConfig()
		cfg.MaxConcurrentReqs = maxPlatformInt + 1
		cfg.normalize()
		if cfg.MaxConcurrentReqs != defaultMaxRequests {
			t.Fatalf("oversized platform-int request limit not rejected: got %d", cfg.MaxConcurrentReqs)
		}
	}
}

func TestGlobalConnectionAdmissionIsNonBlockingAtLimit(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	for i := int64(0); i < g.cfg.MaxGlobalConns; i++ {
		if !g.admitGlobal() {
			t.Fatalf("connection %d rejected below configured global limit", i+1)
		}
	}
	if g.admitGlobal() {
		t.Fatal("connection over the configured global limit should be rejected immediately")
	}
	for i := int64(0); i < g.cfg.MaxGlobalConns; i++ {
		g.releaseGlobal()
	}
	if !g.admitGlobal() {
		t.Fatal("global slot was not released")
	}
	g.releaseGlobal()
}

func TestHealthEndpointChecksBackendTCP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	backend.Close()

	listener, err := net.Listen("tcp", backendAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = backendAddr
	g := NewGuard(cfg)
	source := "192.0.2.76"
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now()) || !g.admitGlobal() {
		t.Fatal("request admission failed")
	}
	defer func() {
		g.states.releaseConn(source)
		g.releaseGlobal()
	}()

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req, err := http.NewRequest(method, "http://guard/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: source, guard: g}))
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s health status = %d, want 200", method, w.Code)
		}
	}

	listener.Close()
	req, err := http.NewRequest(http.MethodGet, "http://guard/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: source, guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy status = %d, want 503", w.Code)
	}
}

func TestDoHProxySanitizesForwardedClientIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.200" {
			t.Fatalf("backend saw spoofable client IP header %q", got)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("10.0.0.2", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("10.0.0.2")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE=", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "10.0.0.2", trusted: true, guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestEnvOverrideReplacesExistingValues(t *testing.T) {
	env := []string{"PATH=/usr/bin", "GOMEMLIMIT=64MiB", "GOMEMLIMIT=96MiB", "LANG=C"}
	got := envOverride(env, "GOMEMLIMIT", "288MiB")
	count := 0
	for _, item := range got {
		if strings.HasPrefix(item, "GOMEMLIMIT=") {
			count++
			if item != "GOMEMLIMIT=288MiB" {
				t.Fatalf("unexpected GOMEMLIMIT entry: %q", item)
			}
		}
	}
	if count != 1 {
		t.Fatalf("GOMEMLIMIT entry count = %d, want 1", count)
	}
}

func TestNormalizeClampsUnsafeValues(t *testing.T) {
	cfg := GuardConfig{
		MaxGlobalConns:         0,
		MaxPerIPConns:          0,
		MaxSourceStates:        0,
		MaxDNSMessage:          0,
		MaxQueriesPerConn:      0,
		MaxConcurrentReqs:      0,
		MaxConcurrentReqsPerIP: 0,
		MaxUpstreamConns:       0,
		MaxHeaderBytes:         1,
		MaxResponseBytes:       1,
	}
	cfg.normalize()
	defaults := defaultGuardConfig()
	for name, values := range map[string][2]int64{
		"global":          {cfg.MaxGlobalConns, defaults.MaxGlobalConns},
		"per-ip":          {int64(cfg.MaxPerIPConns), int64(defaults.MaxPerIPConns)},
		"states":          {int64(cfg.MaxSourceStates), int64(defaults.MaxSourceStates)},
		"dns-size":        {int64(cfg.MaxDNSMessage), int64(defaults.MaxDNSMessage)},
		"queries":         {int64(cfg.MaxQueriesPerConn), int64(defaults.MaxQueriesPerConn)},
		"requests":        {cfg.MaxConcurrentReqs, defaults.MaxConcurrentReqs},
		"requests-per-ip": {int64(cfg.MaxConcurrentReqsPerIP), int64(defaults.MaxConcurrentReqsPerIP)},
		"upstream-conns":  {int64(cfg.MaxUpstreamConns), int64(defaults.MaxUpstreamConns)},
	} {
		if values[0] != values[1] {
			t.Fatalf("%s: got %d, want %d", name, values[0], values[1])
		}
	}
	if cfg.MaxHeaderBytes != defaults.MaxHeaderBytes {
		t.Fatalf("header bytes: got %d, want %d", cfg.MaxHeaderBytes, defaults.MaxHeaderBytes)
	}
	if cfg.MaxResponseBytes != defaults.MaxResponseBytes {
		t.Fatalf("response bytes: got %d, want %d", cfg.MaxResponseBytes, defaults.MaxResponseBytes)
	}
}

func TestEnvUint32RejectsOverflowAndNegative(t *testing.T) {
	t.Setenv("GUARD_MAX_QUERIES_PER_CONN", "4294967296")
	if got := envUint32("GUARD_MAX_QUERIES_PER_CONN", 50); got != 50 {
		t.Fatalf("overflowing uint32 env accepted: got %d", got)
	}

	t.Setenv("GUARD_MAX_QUERIES_PER_CONN", "-1")
	if got := envUint32("GUARD_MAX_QUERIES_PER_CONN", 50); got != 50 {
		t.Fatalf("negative uint32 env accepted: got %d", got)
	}

	t.Setenv("GUARD_MAX_QUERIES_PER_CONN", "4294967295")
	if got := envUint32("GUARD_MAX_QUERIES_PER_CONN", 50); got != ^uint32(0) {
		t.Fatalf("maximum uint32 env rejected: got %d", got)
	}
}

func TestEnvInt32RejectsOverflowAndNegative(t *testing.T) {
	t.Setenv("IP_CONN_LIMIT", "2147483648")
	if got := envInt32("IP_CONN_LIMIT", 50); got != 50 {
		t.Fatalf("overflowing int32 env accepted: got %d", got)
	}

	t.Setenv("IP_CONN_LIMIT", "-1")
	if got := envInt32("IP_CONN_LIMIT", 50); got != 50 {
		t.Fatalf("negative int32 env accepted: got %d", got)
	}

	t.Setenv("IP_CONN_LIMIT", "2147483647")
	if got := envInt32("IP_CONN_LIMIT", 50); got != 2147483647 {
		t.Fatalf("maximum int32 env rejected: got %d", got)
	}
}

func TestClientIPHeaderCanBeExplicitlyDisabled(t *testing.T) {
	t.Setenv("GUARD_CLIENT_IP_HEADER", "")
	cfg := loadGuardConfig()
	if cfg.ClientIPHeader != "" {
		t.Fatalf("empty forwarded-client header env did not disable header: %q", cfg.ClientIPHeader)
	}
}

func TestDropHTTPPreservesStatusWithoutHijacker(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	w := newCaptureWriter()
	g.dropHTTP(w, http.StatusServiceUnavailable)
	if w.status != http.StatusServiceUnavailable {
		t.Fatalf("HTTP/2 rejection status = %d, want %d", w.status, http.StatusServiceUnavailable)
	}
}

func TestDoHProxyNormalizesGETQueryAndBackendHost(t *testing.T) {
	var backend *httptest.Server
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			t.Errorf("backend path = %q, want /dns-query", r.URL.Path)
		}
		if got := r.URL.RawQuery; got != "dns=AAE" {
			t.Errorf("backend query = %q, want dns=AAE", got)
		}
		expectedHost := strings.TrimPrefix(backend.URL, "http://")
		if got := r.Host; got != expectedHost {
			t.Errorf("backend Host = %q, want %q", got, expectedHost)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.77", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.77")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE&extra=ignored&dns=bad", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example"
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.77", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestDoHProxyAllows100SequentialRequestsWithoutApplicationRateLimiter(t *testing.T) {
	calls := atomic.Int64{}
	cfg := defaultGuardConfig()
	g := NewGuard(cfg)
	g.backend = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/dns-message"},
			},
			Body:          io.NopCloser(bytes.NewReader(testDNSResponse())),
			ContentLength: int64(len(testDNSResponse())),
			Request:       r,
		}, nil
	})}
	state := &trackedConn{source: "203.0.113.100", guard: g}
	for i := 0; i < 100; i++ {
		req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, state))
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status=%d, want 200", i+1, w.Code)
		}
	}
	if got := calls.Load(); got != 100 {
		t.Fatalf("backend calls = %d, want 100", got)
	}
}

func TestDoHProxyDoesNotFollowBackendRedirects(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0x09, 0x09})
	}))
	defer target.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/dns-query", http.StatusFound)
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.78", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.78")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.78", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("backend redirect was followed: target hits=%d", got)
	}
}

func TestDoHProxyRejectsOversizedBackendResponseHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", 32*1024))
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.MaxHeaderBytes = 16 << 10
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.79", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.79")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.79", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDoHProxyNormalizesSuccessfulResponseHeaders(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.BackendHTTP = "127.0.0.1:4002"
	g := NewGuard(cfg)
	g.backend = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"text/plain"},
				"Content-Length": []string{"1"},
			},
			Body:          io.NopCloser(bytes.NewReader(testDNSResponse())),
			ContentLength: -1,
			Request:       r,
		}, nil
	})}
	state := &trackedConn{source: "192.0.2.88", guard: g}
	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, state))
	w := newCaptureWriter()
	g.Handler().ServeHTTP(w, req)
	if w.status != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.status)
	}
	if got := w.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("content type = %q", got)
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(w.body.Len()) {
		t.Fatalf("content length = %q, want %d", got, w.body.Len())
	}
}

func TestDoHProxyRejectsUnknownLengthOversizedBackendResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte{0x01}, 513))
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.MaxResponseBytes = 512
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.82", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.82")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.82", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestResponseHopByHopHeadersIncludesStandardAndNominated(t *testing.T) {
	headers := make(http.Header)
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Backend-Only",
		"X-End-To-End",
	} {
		headers.Set(name, "value")
	}
	headers.Set("Connection", "X-Backend-Only")

	hopByHop := responseHopByHopHeaders(headers)
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Backend-Only",
	} {
		if _, ok := hopByHop[http.CanonicalHeaderKey(name)]; !ok {
			t.Fatalf("header %q was not classified as hop-by-hop", name)
		}
	}
	if _, ok := hopByHop[http.CanonicalHeaderKey("X-End-To-End")]; ok {
		t.Fatal("end-to-end header was incorrectly classified as hop-by-hop")
	}
}

func TestDoHProxyDoesNotForwardStandardHopByHopHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{
			"Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailer",
			"Upgrade",
		} {
			w.Header().Set(name, "sensitive")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("X-End-To-End", "keep")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.81", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.81")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.81", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		if got := w.Header().Get(name); got != "" {
			t.Fatalf("standard hop-by-hop response header %q leaked: %q", name, got)
		}
	}
	if got := w.Header().Get("X-End-To-End"); got != "keep" {
		t.Fatalf("end-to-end response header missing: %q", got)
	}
}

func TestDoHProxyDoesNotForwardConnectionNominatedHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Backend-Only")
		w.Header().Set("X-Backend-Only", "secret")
		w.Header().Set("X-End-To-End", "keep")
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.80", cfg.MaxPerIPConns, time.Now())
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.80")
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.80", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	if got := w.Header().Get("X-Backend-Only"); got != "" {
		t.Fatalf("connection-nominated response header leaked: %q", got)
	}
	if got := w.Header().Get("X-End-To-End"); got != "keep" {
		t.Fatalf("end-to-end response header missing: %q", got)
	}
	if got := w.Header().Get("Connection"); got != "" {
		t.Fatalf("Connection response header leaked: %q", got)
	}
}

func TestSourceKeyGroupsIPv6ByPrefix(t *testing.T) {
	a := canonicalIPKey(net.ParseIP("2001:db8:1:2:aaaa::1"))
	b := canonicalIPKey(net.ParseIP("2001:db8:1:2:bbbb::2"))
	c := canonicalIPKey(net.ParseIP("2001:db8:1:3::1"))
	if a != b {
		t.Fatalf("addresses in one /64 got different keys: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("addresses in different /64s share a key: %q", a)
	}
}

func TestIsInternalIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1":    true,
		"10.1.2.3":     true,
		"172.16.0.9":   true,
		"192.168.1.1":  true,
		"100.64.0.1":   true,
		"169.254.1.1":  true,
		"fd00::1":      true,
		"::1":          true,
		"8.8.8.8":      false,
		"100.128.0.1":  false,
		"2001:db8::1":  false,
		"203.0.113.10": false,
	} {
		if got := isInternalIP(net.ParseIP(ip)); got != want {
			t.Errorf("isInternalIP(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestClientIPFromHeaderIgnoresClientInjectedValues(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.5")
	ip, ok := clientIPFromHeader(h, "X-Forwarded-For")
	if !ok || ip.String() != "203.0.113.5" {
		t.Fatalf("got %v %v, want final public value 203.0.113.5", ip, ok)
	}

	h.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.5, 10.0.0.2")
	if _, ok := clientIPFromHeader(h, "X-Forwarded-For"); ok {
		t.Fatal("internal final forwarding value should be rejected")
	}

	h.Set("X-Forwarded-For", "203.0.113.5, not-an-ip")
	if _, ok := clientIPFromHeader(h, "X-Forwarded-For"); ok {
		t.Fatal("malformed header was trusted")
	}

	h.Set("X-Forwarded-For", "10.0.0.7, 192.168.0.1")
	if _, ok := clientIPFromHeader(h, "X-Forwarded-For"); ok {
		t.Fatal("all-internal header should fall back to the peer")
	}

	if _, ok := clientIPFromHeader(make(http.Header), "X-Forwarded-For"); ok {
		t.Fatal("missing header was trusted")
	}
}

func TestLastQueryClosesConnectionGracefully(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.MaxQueriesPerConn = 2
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	conn := &trackedConn{source: "192.0.2.90", guard: g}

	serve := func() *httptest.ResponseRecorder {
		req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, conn))
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		return w
	}

	if w := serve(); w.Code != http.StatusOK || w.Header().Get("Connection") != "" {
		t.Fatalf("first query: status=%d connection=%q", w.Code, w.Header().Get("Connection"))
	}
	if w := serve(); w.Code != http.StatusOK || w.Header().Get("Connection") != "close" {
		t.Fatalf("final query: status=%d connection=%q", w.Code, w.Header().Get("Connection"))
	}
	if w := serve(); w.Code != http.StatusTooManyRequests {
		t.Fatalf("query over the cap: status=%d", w.Code)
	}
}

func TestClientDisconnectIsNotConvertedTo502(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	const source = "192.0.2.91"
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now()) || !g.admitGlobal() {
		t.Fatal("request admission failed")
	}
	defer func() {
		g.states.releaseConn(source)
		g.releaseGlobal()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := &trackedConn{source: source, guard: g}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, conn))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("cancelled request produced a response: status=%d body=%q", w.Code, w.Body.String())
	}
	if hits := backendHits.Load(); hits != 0 {
		t.Fatalf("cancelled request reached backend: hits=%d", hits)
	}
}

func TestBackendTimeoutReturns502(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendTimeout = 10 * time.Millisecond
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	const source = "192.0.2.92"
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now()) || !g.admitGlobal() {
		t.Fatal("request admission failed")
	}
	defer func() {
		g.states.releaseConn(source)
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: source, guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("backend timeout status=%d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestInvalidBackendDNSResponseReturns502(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0x00, 0x01, 0x81})
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	const source = "192.0.2.93"
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now()) || !g.admitGlobal() {
		t.Fatal("request admission failed")
	}
	defer func() {
		g.states.releaseConn(source)
		g.releaseGlobal()
	}()

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: source, guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("invalid backend DNS response status=%d, want %d", w.Code, http.StatusBadGateway)
	}
}
