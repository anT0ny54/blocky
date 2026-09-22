package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSourceTableIsBounded(t *testing.T) {
	table := newSourceTable(128, 10, 20)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		key := "192.0.2." + strconvItoa(i%250)
		_ = table.getOrCreate(key, now.Add(time.Duration(i)*time.Millisecond), 10, 20)
	}
	if got := table.stateCount(); got > 128 {
		t.Fatalf("state table exceeded bound: got %d", got)
	}
}

func TestTokenBucketRateAndBurst(t *testing.T) {
	table := newSourceTable(64, 10, 2)
	now := time.Now()
	key := "198.51.100.7"
	st := table.getOrCreate(key, now, 10, 2)
	if st == nil {
		t.Fatal("state was not created")
	}
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

func TestPerIPConnectionLimit(t *testing.T) {
	table := newSourceTable(64, 10, 20)
	now := time.Now()
	key := "203.0.113.9"
	if _, ok := table.admitConn(key, 2, now, 10, 20); !ok {
		t.Fatal("first connection rejected")
	}
	if _, ok := table.admitConn(key, 2, now, 10, 20); !ok {
		t.Fatal("second connection rejected")
	}
	if _, ok := table.admitConn(key, 2, now, 10, 20); ok {
		t.Fatal("third connection should be rejected")
	}
	table.releaseConn(key)
	if _, ok := table.admitConn(key, 2, now, 10, 20); !ok {
		t.Fatal("connection should be admitted after release")
	}
}

func TestSourceKeyCanonicalizesIPv4MappedIPv6(t *testing.T) {
	got, ok := sourceKey(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.44"), Port: 1234})
	if !ok || got != "192.0.2.44" {
		t.Fatalf("unexpected source key: %q %v", got, ok)
	}
}

func TestTrackedConnCloseReleasesCounters(t *testing.T) {
	g := NewGuard(defaultGuardConfig())
	server, client := net.Pipe()
	defer client.Close()
	state, ok := g.states.admitConn("192.0.2.55", g.cfg.MaxPerIPConns, time.Now(), g.cfg.Rate, g.cfg.Burst)
	if !ok {
		t.Fatal("connection admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	tracked := &trackedConn{Conn: server, guard: g, source: "192.0.2.55", state: state}
	if got := g.globalCon.Load(); got != 1 {
		t.Fatalf("global count before close = %d", got)
	}
	_ = tracked.Close()
	if got := g.globalCon.Load(); got != 0 {
		t.Fatalf("global count after close = %d", got)
	}
}

func strconvItoa(i int) string {
	if i == 0 {
		return "0"
	}
	buf := [20]byte{}
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
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
		_, _ = w.Write([]byte{0x01, 0x02})
	}))
	defer backend.Close()

	cfg := defaultGuardConfig()
	cfg.BackendHTTP = strings.TrimPrefix(backend.URL, "http://")
	g := NewGuard(cfg)
	state, ok := g.states.admitConn("192.0.2.77", cfg.MaxPerIPConns, time.Now(), cfg.Rate, cfg.Burst)
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
	req = req.WithContext(context.WithValue(req.Context(), connStateKey{}, &trackedConn{source: "192.0.2.77", state: state, guard: g}))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
}

func TestDNSTCPFrameLimitClosesBeforeBackendDial(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxDNSMessage = 64
	g := NewGuard(cfg)
	server, client := net.Pipe()
	state, ok := g.states.admitConn("198.51.100.18", cfg.MaxPerIPConns, time.Now(), cfg.Rate, cfg.Burst)
	if !ok {
		t.Fatal("connection state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	tracked := &trackedConn{Conn: server, guard: g, source: "198.51.100.18", state: state}
	done := make(chan struct{})
	go func() {
		g.handleDNSTCP(context.Background(), tracked, "127.0.0.1:1")
		close(done)
	}()
	if _, err := client.Write([]byte{0x00, 0x41}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("oversized DNS TCP frame did not close promptly")
	}
	_ = client.Close()
	if got := g.globalCon.Load(); got != 0 {
		t.Fatalf("global connection count leaked: %d", got)
	}
}

func TestDNSTCPRejectsOversizedBackendResponse(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxDNSMessage = 64
	cfg.BackendTimeout = time.Second
	g := NewGuard(cfg)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		frameLen := int(hdr[0])<<8 | int(hdr[1])
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(conn, frame); err != nil {
			return
		}
		// Send a legal DNS-over-TCP length field that exceeds the guard limit.
		hdr[0], hdr[1] = 0x01, 0x00
		_, _ = conn.Write(hdr[:])
	}()

	server, client := net.Pipe()
	state, ok := g.states.admitConn("198.51.100.19", cfg.MaxPerIPConns, time.Now(), cfg.Rate, cfg.Burst)
	if !ok {
		t.Fatal("connection state admission failed")
	}
	if !g.admitGlobal() {
		t.Fatal("global connection admission failed")
	}
	tracked := &trackedConn{Conn: server, guard: g, source: "198.51.100.19", state: state}
	done := make(chan struct{})
	go func() {
		g.handleDNSTCP(context.Background(), tracked, backendLn.Addr().String())
		close(done)
	}()

	query := make([]byte, 4)
	query[0], query[1] = 0x00, 0x02
	query[2], query[3] = 0x01, 0x02
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("oversized backend response did not close promptly")
	}
	_ = client.Close()
	select {
	case <-backendDone:
	case <-time.After(time.Second):
		t.Fatal("backend test server did not finish")
	}
	if got := g.globalCon.Load(); got != 0 {
		t.Fatalf("global connection count leaked: %d", got)
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

func TestServeDNSUDPDropsOversizedPacketSilently(t *testing.T) {
	cfg := defaultGuardConfig()
	cfg.MaxDNSMessage = 64
	cfg.BackendTimeout = 100 * time.Millisecond
	cfg.WriteTimeout = 100 * time.Millisecond
	g := NewGuard(cfg)

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.serveDNSUDPConn(ctx, server, "127.0.0.1:1") }()

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	oversized := bytes.Repeat([]byte{0x7f}, cfg.MaxDNSMessage+1)
	if _, err := client.Write(oversized); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 512)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("oversized UDP packet unexpectedly received a response")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UDP server returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP server did not stop after cancellation")
	}
}
