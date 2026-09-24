package main

import (
	"bytes"
	"context"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
		_ = table.allow(key, now.Add(time.Duration(i)*time.Millisecond), 10, 20)
	}
	if got := table.stateCount(); got > 128 {
		t.Fatalf("state table exceeded bound: got %d", got)
	}
}

func TestDefaultGuardRateAndBurst(t *testing.T) {
	cfg := defaultGuardConfig()
	if cfg.Rate != defaultRate {
		t.Fatalf("default rate = %v, want %v", cfg.Rate, defaultRate)
	}
	if cfg.Burst != defaultBurst {
		t.Fatalf("default burst = %v, want %v", cfg.Burst, defaultBurst)
	}
	if cfg.Burst < cfg.Rate {
		t.Fatalf("default burst = %v is below default rate = %v", cfg.Burst, cfg.Rate)
	}
}

func TestDefaultStrictDoHProfile(t *testing.T) {
	cfg := defaultGuardConfig()
	if cfg.Rate != 12 || cfg.Burst != 200 {
		t.Fatalf("DoH rate/burst = %v/%v, want 12/200", cfg.Rate, cfg.Burst)
	}
	if cfg.GlobalRate != 80 || cfg.GlobalBurst != 200 {
		t.Fatalf("global rate/burst = %v/%v, want 80/200", cfg.GlobalRate, cfg.GlobalBurst)
	}
	if cfg.MaxPerIPConns != 32 {
		t.Fatalf("per-IP connections = %d, want 32", cfg.MaxPerIPConns)
	}
	if cfg.BackendTimeout != 6*time.Second {
		t.Fatalf("server timeout = %s, want 6s", cfg.BackendTimeout)
	}
}

func TestStrictDoHEnvironmentOverrides(t *testing.T) {
	t.Setenv("DOH_RATE_LIMIT", "13")
	t.Setenv("DOH_RATE_BURST", "201")
	t.Setenv("GLOBAL_RATE_LIMIT", "81")
	t.Setenv("GLOBAL_RATE_BURST", "202")
	t.Setenv("IP_CONN_LIMIT", "33")
	t.Setenv("SERVER_TIMEOUT", "7")
	// Legacy variables must not override the canonical strict-DoH settings.
	t.Setenv("GUARD_RATE", "1")
	t.Setenv("GUARD_BURST", "2")
	t.Setenv("GUARD_MAX_IP_CONNS", "3")
	t.Setenv("GUARD_BACKEND_TIMEOUT", "1s")

	cfg := loadGuardConfig()
	if cfg.Rate != 13 || cfg.Burst != 201 || cfg.GlobalRate != 81 || cfg.GlobalBurst != 202 {
		t.Fatalf("strict DoH env override mismatch: rate=%v/%v global=%v/%v", cfg.Rate, cfg.Burst, cfg.GlobalRate, cfg.GlobalBurst)
	}
	if cfg.MaxPerIPConns != 33 || cfg.BackendTimeout != 7*time.Second {
		t.Fatalf("strict DoH env connection/timeout mismatch: ip-conns=%d timeout=%s", cfg.MaxPerIPConns, cfg.BackendTimeout)
	}
}

func TestGlobalRateLimit(t *testing.T) {
	b := newTokenBucket(1, 2)
	now := time.Now()
	if !b.allow(now) || !b.allow(now) {
		t.Fatal("global burst did not allow two immediate requests")
	}
	if b.allow(now) {
		t.Fatal("global rate limiter allowed a request over burst")
	}
	if !b.allow(now.Add(time.Second)) {
		t.Fatal("global rate limiter did not replenish at the configured rate")
	}
}

func TestDefaultBurstAllowsBurstImmediateRequests(t *testing.T) {
	cfg := defaultGuardConfig()
	table := newSourceTable(64)
	now := time.Unix(1000, 0)
	key := "198.51.100.30"
	burst := int(cfg.Burst)
	for i := 0; i < burst; i++ {
		if !table.allow(key, now, cfg.Rate, cfg.Burst) {
			t.Fatalf("request %d of %d was rejected", i+1, burst)
		}
	}
	if table.allow(key, now, cfg.Rate, cfg.Burst) {
		t.Fatalf("request %d was accepted immediately; burst should be %d", burst+1, burst)
	}
}

func TestTokenBucketRateAndBurst(t *testing.T) {
	table := newSourceTable(64)
	now := time.Now()
	key := "198.51.100.7"
	if !table.allow(key, now, 10, 2) {
		t.Fatal("first token was rejected")
	}
	if !table.allow(key, now, 10, 2) {
		t.Fatal("burst token was rejected")
	}
	if table.allow(key, now, 10, 2) {
		t.Fatal("third immediate token should be rejected")
	}
	if !table.allow(key, now.Add(100*time.Millisecond), 10, 2) {
		t.Fatal("refilled token was rejected")
	}
}

func TestSourceRateBucketsArePerIP(t *testing.T) {
	table := newSourceTable(64)
	now := time.Unix(1000, 0)
	key := "198.51.100.20"

	if !table.allow(key, now, 1, 1) {
		t.Fatal("first request was rejected")
	}
	if table.allow(key, now, 1, 1) {
		t.Fatal("second immediate request should be rejected")
	}
	if !table.allow(key, now.Add(time.Second), 1, 1) {
		t.Fatal("rate bucket did not refill for the same source IP")
	}
}

func TestPerIPConnectionLimit(t *testing.T) {
	table := newSourceTable(64)
	now := time.Now()
	key := "203.0.113.9"
	if !table.admitConn(key, 2, now, 20) {
		t.Fatal("first connection rejected")
	}
	if !table.admitConn(key, 2, now, 20) {
		t.Fatal("second connection rejected")
	}
	if table.admitConn(key, 2, now, 20) {
		t.Fatal("third connection should be rejected")
	}
	table.releaseConn(key)
	if !table.admitConn(key, 2, now, 20) {
		t.Fatal("connection should be admitted after release")
	}
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
	ok := g.states.admitConn("192.0.2.55", g.cfg.MaxPerIPConns, time.Now(), g.cfg.Burst)
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

func TestGlobalConnectionAdmissionIsNonBlockingAtLimit(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	g.cfg.MaxGlobalConns = 1
	if !g.admitGlobal() {
		t.Fatal("first global connection rejected")
	}
	if g.admitGlobal() {
		t.Fatal("second global connection should be rejected immediately")
	}
	g.releaseGlobal()
	if !g.admitGlobal() {
		t.Fatal("global slot was not released")
	}
}

func TestDoHProxySanitizesForwardedClientIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "192.0.2.77" {
			t.Fatalf("backend saw spoofable client IP header %q", got)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.77", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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

	req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE=", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.77", guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestNormalizeClampsUnsafeValues(t *testing.T) {
	cfg := GuardConfig{
		Rate:              -1,
		Burst:             0,
		MaxGlobalConns:    0,
		MaxPerIPConns:     0,
		MaxSourceStates:   0,
		MaxDNSMessage:     0,
		MaxQueriesPerConn: 0,
		MaxConcurrentReqs: 0,
		MaxHeaderBytes:    1,
		MaxResponseBytes:  1,
	}
	cfg.normalize()
	defaults := defaultGuardConfig()
	for name, values := range map[string][2]int64{
		"global":   {cfg.MaxGlobalConns, defaults.MaxGlobalConns},
		"per-ip":   {int64(cfg.MaxPerIPConns), int64(defaults.MaxPerIPConns)},
		"states":   {int64(cfg.MaxSourceStates), int64(defaults.MaxSourceStates)},
		"dns-size": {int64(cfg.MaxDNSMessage), int64(defaults.MaxDNSMessage)},
		"queries":  {int64(cfg.MaxQueriesPerConn), int64(defaults.MaxQueriesPerConn)},
		"requests": {cfg.MaxConcurrentReqs, defaults.MaxConcurrentReqs},
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

func TestNormalizeRejectsNonFiniteRateValues(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.Rate = math.NaN()
	cfg.Burst = math.Inf(1)
	cfg.normalize()
	if cfg.Rate != defaultRate {
		t.Fatalf("rate: got %v, want %v", cfg.Rate, defaultRate)
	}
	if cfg.Burst != defaultBurst {
		t.Fatalf("burst: got %v, want %v", cfg.Burst, defaultBurst)
	}

	cfg = defaultGuardConfig()
	cfg.Rate = math.Inf(1)
	cfg.Burst = 1
	cfg.normalize()
	if cfg.Rate != defaultRate {
		t.Fatalf("infinite rate: got %v, want %v", cfg.Rate, defaultRate)
	}
	if cfg.Burst != defaultRate {
		t.Fatalf("burst below normalized rate: got %v, want %v", cfg.Burst, defaultRate)
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
	if got := envUint32("GUARD_MAX_QUERIES_PER_CONN", 50); got != math.MaxUint32 {
		t.Fatalf("maximum uint32 env rejected: got %d", got)
	}
}

func TestDoHRateLimitCannotBeFragmentedByHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	ok := g.states.admitConn("192.0.2.76", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
	if !ok {
		t.Fatal("client state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	defer func() {
		g.states.releaseConn("192.0.2.76")
		g.releaseGlobal()
	}()

	newRequest := func(host string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		return req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.76", guard: g}))
	}

	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, newRequest("one.example"))
	if w.Code != http.StatusOK {
		t.Fatalf("first request status: %d", w.Code)
	}

	w = httptest.NewRecorder()
	g.Handler().ServeHTTP(w, newRequest("two.example"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request with another Host bypassed rate limit: status=%d", w.Code)
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
	ok := g.states.admitConn("192.0.2.77", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	ok := g.states.admitConn("192.0.2.78", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	ok := g.states.admitConn("192.0.2.79", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	ok := g.states.admitConn("192.0.2.82", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	ok := g.states.admitConn("192.0.2.81", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	ok := g.states.admitConn("192.0.2.80", cfg.MaxPerIPConns, time.Now(), cfg.Burst)
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
	h.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.5, 10.0.0.2")
	ip, ok := clientIPFromHeader(h, "X-Forwarded-For")
	if !ok || ip.String() != "203.0.113.5" {
		t.Fatalf("got %v %v, want the right-most public hop 203.0.113.5", ip, ok)
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

func TestTrustedProxyRateLimitsByForwardedClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.50" && got != "203.0.113.51" {
			t.Errorf("backend saw client %q", got)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testDNSResponse())
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.Rate = 1
	cfg.Burst = 1
	cfg.ClientIPHeader = "X-Forwarded-For"
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	conn := &trackedConn{source: "10.0.0.2", guard: g, trusted: true}

	serve := func(client string) int {
		req, err := http.NewRequest(http.MethodGet, "http://guard/dns-query?dns=AAE", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-For", client)
		req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, conn))
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		return w.Code
	}

	if got := serve("203.0.113.50"); got != http.StatusOK {
		t.Fatalf("first client status: %d", got)
	}
	if got := serve("203.0.113.50"); got != http.StatusTooManyRequests {
		t.Fatalf("same client over its limit got status %d", got)
	}
	if got := serve("203.0.113.51"); got != http.StatusOK {
		t.Fatalf("a different client behind the same proxy was throttled: %d", got)
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
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now(), cfg.Burst) || !g.admitGlobal() {
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
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now(), cfg.Burst) || !g.admitGlobal() {
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
	if !g.states.admitConn(source, cfg.MaxPerIPConns, time.Now(), cfg.Burst) || !g.admitGlobal() {
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
