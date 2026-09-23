package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultListenAddr       = ":4001"
	defaultBackendHTTP      = "127.0.0.1:4002"
	defaultDohPath          = "/dns-query"
	defaultRate             = 10.0
	defaultBurst            = 24.0
	defaultGlobalConns      = 96
	defaultPerIPConns       = 12
	defaultMaxSourceStates  = 512
	defaultMaxDNSMessage    = 4096
	defaultMaxQueriesConn   = 50
	defaultMaxHeaderBytes   = 16 << 10
	defaultResponseMaxBytes = 65535
	defaultStateIdle        = 2 * time.Minute
	defaultReadHeader       = 5 * time.Second
	defaultReadTimeout      = 10 * time.Second
	defaultWriteTimeout     = 10 * time.Second
	defaultIdleTimeout      = 20 * time.Second
	defaultBackendTimeout   = 5 * time.Second
	defaultMaxRequests      = 64

	stateShards = 64
)

// GuardConfig intentionally stays independent from Blocky's resolver-chain rate
// limiter. This layer protects the public socket/request path before Blocky parses
// or resolves the DNS message.
type GuardConfig struct {
	ListenAddr        string
	BackendHTTP       string
	DOHPath           string
	Rate              float64
	Burst             float64
	MaxGlobalConns    int64
	MaxPerIPConns     int32
	MaxSourceStates   int
	MaxDNSMessage     int
	MaxQueriesPerConn uint32
	MaxConcurrentReqs int64
	StateIdle         time.Duration
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	BackendTimeout    time.Duration
	MaxHeaderBytes    int
	MaxResponseBytes  int64
}

func defaultGuardConfig() GuardConfig {
	return GuardConfig{
		ListenAddr:        defaultListenAddr,
		BackendHTTP:       defaultBackendHTTP,
		DOHPath:           defaultDohPath,
		Rate:              defaultRate,
		Burst:             defaultBurst,
		MaxGlobalConns:    defaultGlobalConns,
		MaxPerIPConns:     defaultPerIPConns,
		MaxSourceStates:   defaultMaxSourceStates,
		MaxDNSMessage:     defaultMaxDNSMessage,
		MaxQueriesPerConn: defaultMaxQueriesConn,
		MaxConcurrentReqs: defaultMaxRequests,
		StateIdle:         defaultStateIdle,
		ReadHeaderTimeout: defaultReadHeader,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		BackendTimeout:    defaultBackendTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
		MaxResponseBytes:  defaultResponseMaxBytes,
	}
}

func loadGuardConfig() GuardConfig {
	c := defaultGuardConfig()
	c.ListenAddr = envString("GUARD_LISTEN", c.ListenAddr)
	c.BackendHTTP = envString("GUARD_BACKEND", c.BackendHTTP)
	c.DOHPath = envString("GUARD_DOH_PATH", c.DOHPath)
	c.Rate = envFloat("GUARD_RATE", c.Rate)
	c.Burst = envFloat("GUARD_BURST", c.Burst)
	c.MaxGlobalConns = envInt64("GUARD_MAX_GLOBAL_CONNS", c.MaxGlobalConns)
	c.MaxPerIPConns = int32(envInt64("GUARD_MAX_IP_CONNS", int64(c.MaxPerIPConns)))
	c.MaxSourceStates = int(envInt64("GUARD_MAX_IP_STATES", int64(c.MaxSourceStates)))
	c.MaxDNSMessage = int(envInt64("GUARD_MAX_DNS_MESSAGE", int64(c.MaxDNSMessage)))
	c.MaxQueriesPerConn = envUint32("GUARD_MAX_QUERIES_PER_CONN", c.MaxQueriesPerConn)
	c.MaxConcurrentReqs = envInt64("GUARD_MAX_CONCURRENT_REQS", c.MaxConcurrentReqs)
	c.StateIdle = envDuration("GUARD_STATE_IDLE", c.StateIdle)
	c.ReadHeaderTimeout = envDuration("GUARD_READ_HEADER_TIMEOUT", c.ReadHeaderTimeout)
	c.ReadTimeout = envDuration("GUARD_READ_TIMEOUT", c.ReadTimeout)
	c.WriteTimeout = envDuration("GUARD_WRITE_TIMEOUT", c.WriteTimeout)
	c.IdleTimeout = envDuration("GUARD_IDLE_TIMEOUT", c.IdleTimeout)
	c.BackendTimeout = envDuration("GUARD_BACKEND_TIMEOUT", c.BackendTimeout)
	c.MaxHeaderBytes = int(envInt64("GUARD_MAX_HEADER_BYTES", int64(c.MaxHeaderBytes)))
	c.MaxResponseBytes = envInt64("GUARD_MAX_RESPONSE_BYTES", c.MaxResponseBytes)
	c.normalize()
	return c
}

func (c *GuardConfig) normalize() {
	if c.ListenAddr == "" {
		c.ListenAddr = defaultListenAddr
	}
	if c.BackendHTTP == "" {
		c.BackendHTTP = defaultBackendHTTP
	}
	if c.DOHPath == "" || c.DOHPath[0] != '/' {
		c.DOHPath = defaultDohPath
	}
	if c.Rate <= 0 || math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) {
		c.Rate = defaultRate
	}
	if c.Burst <= 0 {
		c.Burst = c.Rate
	} else if math.IsNaN(c.Burst) || math.IsInf(c.Burst, 0) {
		c.Burst = defaultBurst
	}
	if c.Burst < c.Rate {
		c.Burst = c.Rate
	}
	if c.MaxGlobalConns < 1 {
		c.MaxGlobalConns = defaultGlobalConns
	}
	if c.MaxPerIPConns < 1 {
		c.MaxPerIPConns = defaultPerIPConns
	}
	if c.MaxSourceStates < 1 {
		c.MaxSourceStates = defaultMaxSourceStates
	}
	if c.MaxDNSMessage < 64 || c.MaxDNSMessage > 65535 {
		c.MaxDNSMessage = defaultMaxDNSMessage
	}
	if c.MaxQueriesPerConn < 1 {
		c.MaxQueriesPerConn = defaultMaxQueriesConn
	}
	if c.MaxConcurrentReqs < 1 {
		c.MaxConcurrentReqs = defaultMaxRequests
	}
	if c.StateIdle <= 0 {
		c.StateIdle = defaultStateIdle
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = defaultReadHeader
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = defaultReadTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.BackendTimeout <= 0 {
		c.BackendTimeout = defaultBackendTimeout
	}
	if c.MaxHeaderBytes < 1024 {
		c.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if c.MaxResponseBytes < 512 || c.MaxResponseBytes > 65535 {
		c.MaxResponseBytes = defaultResponseMaxBytes
	}
}

func envString(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envInt64(name string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func envFloat(name string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}

func envUint32(name string, fallback uint32) uint32 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return fallback
	}
	return uint32(n)
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return n
}

type clientState struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
	conns    int32
}

type stateShard struct {
	mu      sync.Mutex
	clients map[string]*clientState
}

type sourceTable struct {
	shards     [stateShards]stateShard
	shardLimit [stateShards]int
	shardCount int
	stateIdle  time.Duration
	seed       maphash.Seed
}

func newSourceTable(maxStates int) *sourceTable {
	if maxStates < 1 {
		maxStates = 1
	}
	shardCount := stateShards
	if maxStates < shardCount {
		shardCount = maxStates
	}
	base := maxStates / shardCount
	rem := maxStates % shardCount
	t := &sourceTable{shardCount: shardCount, stateIdle: defaultStateIdle, seed: maphash.MakeSeed()}
	for i := 0; i < shardCount; i++ {
		limit := base
		if i < rem {
			limit++
		}
		t.shardLimit[i] = limit
		t.shards[i].clients = make(map[string]*clientState, limit)
	}
	return t
}

func (t *sourceTable) sourceHash(key string) uint64 {
	// Randomized hashing prevents an external client from precomputing IPs that
	// deliberately collide into the same shard and force churn in one bucket.
	return maphash.String(t.seed, key)
}

func (t *sourceTable) shard(key string) *stateShard {
	return &t.shards[t.sourceHash(key)%uint64(t.shardCount)]
}

func (t *sourceTable) createLocked(shardIdx int, key string, now time.Time, burst float64) *clientState {
	s := &t.shards[shardIdx]
	if len(s.clients) >= t.shardLimit[shardIdx] {
		var victimKey string
		var victim *clientState
		for k, candidate := range s.clients {
			if candidate.conns != 0 {
				continue
			}
			if now.Sub(candidate.lastSeen) >= t.stateIdle {
				victimKey, victim = k, candidate
				break
			}
			if victim == nil || candidate.lastSeen.Before(victim.lastSeen) {
				victimKey, victim = k, candidate
			}
		}
		if victim == nil {
			return nil
		}
		delete(s.clients, victimKey)
	}
	st := &clientState{tokens: burst, last: now, lastSeen: now}
	s.clients[key] = st
	return st
}

func (t *sourceTable) allow(key string, now time.Time, rate, burst float64) bool {
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.clients[key]
	if st == nil {
		return false
	}
	elapsed := now.Sub(st.last).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * rate
		if st.tokens > burst {
			st.tokens = burst
		}
		st.last = now
	}
	st.lastSeen = now
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

// admitOrAllow performs client creation and the token-bucket check under a single
// shard lock, instead of two separate locked calls. This halves the mutex
// acquisitions on the connectionless UDP path, where both steps run for
// every inbound packet.
func (t *sourceTable) admitOrAllow(key string, now time.Time, rate, burst float64) bool {
	shardIdx := t.sourceHash(key) % uint64(t.shardCount)
	s := &t.shards[shardIdx]
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.clients[key]
	if st == nil {
		st = t.createLocked(int(shardIdx), key, now, burst)
		if st == nil {
			return false
		}
	}

	elapsed := now.Sub(st.last).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * rate
		if st.tokens > burst {
			st.tokens = burst
		}
		st.last = now
	}
	st.lastSeen = now
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

func (t *sourceTable) admitConn(key string, max int32, now time.Time, rate, burst float64) (*clientState, bool) {
	shardIdx := t.sourceHash(key) % uint64(t.shardCount)
	s := &t.shards[shardIdx]
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.clients[key]
	if st == nil {
		st = t.createLocked(int(shardIdx), key, now, burst)
		if st == nil {
			return nil, false
		}
	}
	st.lastSeen = now
	if st.conns >= max {
		return st, false
	}
	st.conns++
	return st, true
}

func (t *sourceTable) releaseConn(key string) {
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.clients[key]; st != nil && st.conns > 0 {
		st.conns--
	}
}

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

type Guard struct {
	cfg       GuardConfig
	states    *sourceTable
	globalCon atomic.Int64
	activeReq atomic.Int64
	backend   *http.Client
}

func NewGuard(cfg GuardConfig) *Guard {
	cfg.normalize()
	tr := &http.Transport{
		Proxy:                  nil,
		MaxConnsPerHost:        int(cfg.MaxConcurrentReqs),
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        20 * time.Second,
		ResponseHeaderTimeout:  cfg.BackendTimeout,
		MaxResponseHeaderBytes: int64(cfg.MaxHeaderBytes),
		DisableCompression:     true,
	}
	states := newSourceTable(cfg.MaxSourceStates)
	states.stateIdle = cfg.StateIdle
	return &Guard{
		cfg:    cfg,
		states: states,
		backend: &http.Client{
			Transport: tr,
			Timeout:   cfg.BackendTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (g *Guard) acquireRequest() bool {
	for {
		cur := g.activeReq.Load()
		if cur >= g.cfg.MaxConcurrentReqs {
			return false
		}
		if g.activeReq.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (g *Guard) releaseRequest() {
	g.activeReq.Add(-1)
}

func (g *Guard) admitGlobal() bool {
	for {
		cur := g.globalCon.Load()
		if cur >= g.cfg.MaxGlobalConns {
			return false
		}
		if g.globalCon.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (g *Guard) releaseGlobal() {
	g.globalCon.Add(-1)
}

func sourceKey(addr net.Addr) (string, bool) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.IP == nil {
			return "", false
		}
		ip := a.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ip.String(), true
	case *net.UDPAddr:
		if a.IP == nil {
			return "", false
		}
		ip := a.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ip.String(), true
	default:
		return "", false
	}
}

type trackedConn struct {
	net.Conn
	guard    *Guard
	source   string
	released sync.Once
	queries  atomic.Uint32
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.released.Do(func() {
		c.guard.states.releaseConn(c.source)
		c.guard.releaseGlobal()
	})
	return err
}

func (c *trackedConn) nextQuery(max uint32) bool {
	if max == 0 {
		return true
	}
	n := c.queries.Add(1)
	return n <= max
}

type guardedListener struct {
	inner net.Listener
	guard *Guard
}

func (l *guardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		if !l.guard.admitGlobal() {
			_ = conn.Close()
			continue
		}
		source, ok := sourceKey(conn.RemoteAddr())
		if !ok {
			l.guard.releaseGlobal()
			_ = conn.Close()
			continue
		}
		_, ok = l.guard.states.admitConn(source, l.guard.cfg.MaxPerIPConns, time.Now(), l.guard.cfg.Rate, l.guard.cfg.Burst)
		if !ok {
			_ = conn.Close()
			l.guard.releaseGlobal()
			continue
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		return &trackedConn{Conn: conn, guard: l.guard, source: source}, nil
	}
}

func (l *guardedListener) Close() error {
	return l.inner.Close()
}

func (l *guardedListener) Addr() net.Addr { return l.inner.Addr() }

func (g *Guard) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, ok := r.Context().Value(connStateKey{}).(*trackedConn)
		if !ok || state == nil {
			return
		}
		if !state.nextQuery(g.cfg.MaxQueriesPerConn) {
			g.dropHTTP(w)
			return
		}
		if !g.states.allow(state.source, time.Now(), g.cfg.Rate, g.cfg.Burst) {
			g.dropHTTP(w)
			return
		}
		if !g.acquireRequest() {
			g.dropHTTP(w)
			return
		}
		defer g.releaseRequest()

		if r.URL.Path != g.cfg.DOHPath || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			// Answer platform health/readiness probes (e.g. SnapDeploy's wake
			// check hitting "/") instead of silently hijacking and closing the
			// connection. Only a cheap, static 200 on GET "/" with no body is
			// exempted; everything else still gets dropped.
			if r.URL.Path == "/" && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				return
			}
			g.dropHTTP(w)
			return
		}
		if r.Header.Get("Upgrade") != "" || r.Method == http.MethodConnect {
			g.dropHTTP(w)
			return
		}

		body, err := g.readDoHBody(r)
		if err != nil {
			g.dropHTTP(w)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), g.cfg.BackendTimeout)
		defer cancel()
		var requestBody io.Reader
		if r.Method == http.MethodPost {
			requestBody = bytes.NewReader(body)
		}
		backendURI := g.cfg.DOHPath
		if r.Method == http.MethodGet {
			backendURI += "?dns=" + base64.RawURLEncoding.EncodeToString(body)
		}
		backendReq, err := http.NewRequestWithContext(ctx, r.Method, "http://"+g.cfg.BackendHTTP+backendURI, requestBody)
		if err != nil {
			g.dropHTTP(w)
			return
		}
		backendReq.Header.Set("X-Forwarded-For", state.source)
		if accept := r.Header.Get("Accept"); accept != "" {
			backendReq.Header.Set("Accept", accept)
		}
		if r.Method == http.MethodPost {
			backendReq.Header.Set("Content-Type", "application/dns-message")
		}

		resp, err := g.backend.Do(backendReq)
		if err != nil {
			g.dropHTTP(w)
			return
		}
		defer resp.Body.Close()
		if resp.ContentLength > g.cfg.MaxResponseBytes {
			g.dropHTTP(w)
			return
		}
		hopByHop := responseHopByHopHeaders(resp.Header)
		for k, values := range resp.Header {
			if _, ok := hopByHop[http.CanonicalHeaderKey(k)]; ok {
				continue
			}
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.CopyN(w, resp.Body, g.cfg.MaxResponseBytes)

	})
}

func responseHopByHopHeaders(headers http.Header) map[string]struct{} {
	hopByHop := make(map[string]struct{}, 8)
	for _, name := range []string{
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
	} {
		hopByHop[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token != "" {
				hopByHop[http.CanonicalHeaderKey(token)] = struct{}{}
			}
		}
	}
	return hopByHop
}

func (g *Guard) readDoHBody(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}
		var body []byte
		var err error
		body, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			body, err = base64.URLEncoding.DecodeString(encoded)
		}
		if err != nil || len(body) == 0 || len(body) > g.cfg.MaxDNSMessage {
			return nil, fmt.Errorf("invalid dns query size")
		}
		return body, nil
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil, fmt.Errorf("missing content type")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("invalid content type")
	}
	if r.ContentLength > int64(g.cfg.MaxDNSMessage) {
		return nil, fmt.Errorf("oversized dns message")
	}
	limited := io.LimitReader(r.Body, int64(g.cfg.MaxDNSMessage)+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) == 0 || len(body) > g.cfg.MaxDNSMessage {
		return nil, fmt.Errorf("invalid dns message size")
	}
	return body, nil
}

func (g *Guard) dropHTTP(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
		}
		return
	}
	// HTTP/2 has no Hijacker. The deployment uses the HTTP listener behind the
	// platform proxy, so this is only a defensive fallback for non-HTTP/1 paths.
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusTooManyRequests)
}

type connStateKey struct{}

func (g *Guard) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", g.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", g.cfg.ListenAddr, err)
	}
	defer listener.Close()
	gl := &guardedListener{inner: listener, guard: g}
	srv := &http.Server{
		Handler:           g.Handler(),
		ReadHeaderTimeout: g.cfg.ReadHeaderTimeout,
		ReadTimeout:       g.cfg.ReadTimeout,
		WriteTimeout:      g.cfg.WriteTimeout,
		IdleTimeout:       g.cfg.IdleTimeout,
		MaxHeaderBytes:    g.cfg.MaxHeaderBytes,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connStateKey{}, c)
		},
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(gl); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// ServeDNSTCP provides the requested TCP DNS framing/connection guard for
// deployments that need a raw DNS front-end. It is not enabled by default in
// this SnapDeploy build because the public service is DoH-only.
func (g *Guard) ServeDNSTCP(ctx context.Context, listenAddr, backendAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	gl := &guardedListener{inner: ln, guard: g}
	for {
		conn, err := gl.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go g.handleDNSTCP(ctx, conn, backendAddr)
	}
}

func (g *Guard) handleDNSTCP(ctx context.Context, conn net.Conn, backendAddr string) {
	defer conn.Close()
	state, ok := conn.(*trackedConn)
	if !ok {
		return
	}

	var backend net.Conn
	defer func() {
		if backend != nil {
			_ = backend.Close()
		}
	}()

	for {
		if !state.nextQuery(g.cfg.MaxQueriesPerConn) || !g.states.allow(state.source, time.Now(), g.cfg.Rate, g.cfg.Burst) {
			return
		}
		var hdr [2]byte
		// Bound the wait for the next query's length header. Without this, a
		// client that opens a connection and never sends data holds a global
		// and per-IP connection slot open indefinitely, since this raw framing
		// loop runs outside http.Server and gets none of its idle timeouts.
		_ = conn.SetReadDeadline(time.Now().Add(g.cfg.IdleTimeout))
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		frameLen := int(hdr[0])<<8 | int(hdr[1])
		// Reject the length field before allocating or dialing the backend.
		if frameLen == 0 || frameLen > g.cfg.MaxDNSMessage {
			return
		}
		frame := make([]byte, frameLen)
		_ = conn.SetReadDeadline(time.Now().Add(g.cfg.ReadTimeout))
		if _, err := io.ReadFull(conn, frame); err != nil {
			return
		}

		if !g.acquireRequest() {
			return
		}
		stop := false
		func() {
			defer g.releaseRequest()
			if backend == nil {
				var err error
				backend, err = net.DialTimeout("tcp", backendAddr, g.cfg.BackendTimeout)
				if err != nil {
					stop = true
					return
				}
			}
			_ = backend.SetDeadline(time.Now().Add(g.cfg.BackendTimeout))
			if _, err := backend.Write(hdr[:]); err != nil {
				stop = true
				return
			}
			if _, err := backend.Write(frame); err != nil {
				stop = true
				return
			}
			if _, err := io.ReadFull(backend, hdr[:]); err != nil {
				stop = true
				return
			}
			respLen := int(hdr[0])<<8 | int(hdr[1])
			if respLen == 0 || respLen > g.cfg.MaxDNSMessage {
				stop = true
				return
			}
			resp := make([]byte, respLen)
			if _, err := io.ReadFull(backend, resp); err != nil {
				stop = true
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(g.cfg.WriteTimeout))
			if _, err := conn.Write(hdr[:]); err != nil {
				stop = true
				return
			}
			if _, err := conn.Write(resp); err != nil {
				stop = true
				return
			}
		}()
		if stop {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// ServeDNSUDP provides a silent-drop UDP guard. Oversized, rate-limited, or
// globally saturated packets are dropped without a response.
func (g *Guard) ServeDNSUDP(ctx context.Context, listenAddr, backendAddr string) error {
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return g.serveDNSUDPConn(ctx, conn, backendAddr)
}

func (g *Guard) serveDNSUDPConn(ctx context.Context, conn net.PacketConn, backendAddr string) error {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	bufSize := g.cfg.MaxDNSMessage + 1
	if bufSize < 64 {
		bufSize = 64
	}
	buf := make([]byte, bufSize)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n == 0 || n > g.cfg.MaxDNSMessage {
			continue
		}
		source, ok := sourceKey(client)
		if !ok {
			continue
		}
		now := time.Now()
		if !g.states.admitOrAllow(source, now, g.cfg.Rate, g.cfg.Burst) {
			continue
		}
		if !g.acquireRequest() {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		go func() {
			defer g.releaseRequest()
			deadline := time.Now().Add(g.cfg.BackendTimeout)
			backend, err := net.DialTimeout("udp", backendAddr, g.cfg.BackendTimeout)
			if err != nil {
				return
			}
			defer backend.Close()
			_ = backend.SetDeadline(deadline)
			if _, err := backend.Write(packet); err != nil {
				return
			}
			resp := make([]byte, g.cfg.MaxDNSMessage+1)
			m, err := backend.Read(resp)
			if err != nil || m == 0 || m > g.cfg.MaxDNSMessage {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(g.cfg.WriteTimeout))
			_, _ = conn.WriteTo(resp[:m], client)
		}()
	}
}

func runHealthcheck() error {
	conn, err := net.DialTimeout("udp", "127.0.0.1:5300", 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	query := []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0b, 'h', 'e', 'a', 'l', 't', 'h', 'c', 'h', 'e', 'c', 'k',
		0x06, 'b', 'l', 'o', 'c', 'k', 'y',
		0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := conn.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 12 {
		return fmt.Errorf("short healthcheck response")
	}
	if buf[0] != 0x12 || buf[1] != 0x34 {
		return fmt.Errorf("healthcheck transaction mismatch")
	}
	if buf[2]&0x80 == 0 || buf[3]&0x0f != 0 {
		return fmt.Errorf("healthcheck status failed")
	}
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfg := loadGuardConfig()
	guard := NewGuard(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	blocky := exec.Command("/app/blocky")
	blocky.Stdout = os.Stdout
	blocky.Stderr = os.Stderr
	if err := blocky.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start blocky:", err)
		os.Exit(1)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- guard.Run(ctx) }()
	go func() {
		errCh <- blocky.Wait()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			fmt.Fprintln(os.Stderr, "service stopped:", err)
		}
		stop()
	}

	if blocky.ProcessState == nil || blocky.ProcessState.Exited() == false {
		_ = blocky.Process.Signal(syscall.SIGTERM)
		select {
		case <-time.After(2 * time.Second):
			_ = blocky.Process.Kill()
		case <-errCh:
		}
	}
}
