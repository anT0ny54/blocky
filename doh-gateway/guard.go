package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
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
	defaultHealthPath       = "/healthz"
	defaultGlobalConns      = 256  // GLOBAL_CONN_LIMIT
	defaultPerIPConns       = 64   // IP_CONN_LIMIT
	defaultMaxSourceStates  = 512  // up to 2x the default global connection ceiling
	defaultMaxDNSMessage    = 4096 // DOH_MAX_BODY_BYTES
	defaultMaxQueriesConn   = 1024
	defaultMaxHeaderBytes   = 16 << 10
	defaultResponseMaxBytes = 65535
	defaultStateIdle        = 2 * time.Minute
	defaultReadHeader       = 5 * time.Second
	defaultReadTimeout      = 10 * time.Second
	defaultWriteTimeout     = 10 * time.Second
	defaultIdleTimeout      = 60 * time.Second
	defaultBackendTimeout   = 8 * time.Second // public guard response wait
	defaultBackendDial      = 1 * time.Second
	defaultMaxUpstreamConns = 8  // UPSTREAM_MAX_CONNS: guard -> Blocky loopback pool
	defaultMaxRequests      = 16 // bounded in-flight work above the 8-connection backend pool
	defaultMaxRequestsPerIP = 8
	defaultBlockyMemLimit   = "288MiB"

	stateShards = 16

	// maxInt32 caps the per-source connection limit applied to platform-internal
	// peers, which are bounded by the global connection cap instead.
	maxInt32 = 1<<31 - 1
)

// GuardConfig intentionally stays independent from Blocky's resolver-chain rate
// limiter. This layer protects the public socket/request path before Blocky parses
// or resolves the DNS message.
type GuardConfig struct {
	ListenAddr             string
	BackendHTTP            string
	DOHPath                string
	HealthPath             string
	ClientIPHeader         string
	MaxGlobalConns         int64
	MaxPerIPConns          int32
	MaxSourceStates        int
	MaxDNSMessage          int
	MaxQueriesPerConn      uint32
	MaxConcurrentReqs      int64
	MaxConcurrentReqsPerIP int32
	MaxUpstreamConns       int
	BackendDialTimeout     time.Duration
	StateIdle              time.Duration
	ReadHeaderTimeout      time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	BackendTimeout         time.Duration
	MaxHeaderBytes         int
	MaxResponseBytes       int64
}

func defaultGuardConfig() GuardConfig {
	return GuardConfig{
		ListenAddr:             defaultListenAddr,
		BackendHTTP:            defaultBackendHTTP,
		DOHPath:                defaultDohPath,
		HealthPath:             defaultHealthPath,
		ClientIPHeader:         http.CanonicalHeaderKey("X-Forwarded-For"),
		MaxGlobalConns:         defaultGlobalConns,
		MaxPerIPConns:          defaultPerIPConns,
		MaxSourceStates:        defaultMaxSourceStates,
		MaxDNSMessage:          defaultMaxDNSMessage,
		MaxQueriesPerConn:      defaultMaxQueriesConn,
		MaxConcurrentReqs:      defaultMaxRequests,
		MaxConcurrentReqsPerIP: defaultMaxRequestsPerIP,
		MaxUpstreamConns:       defaultMaxUpstreamConns,
		BackendDialTimeout:     defaultBackendDial,
		StateIdle:              defaultStateIdle,
		ReadHeaderTimeout:      defaultReadHeader,
		ReadTimeout:            defaultReadTimeout,
		WriteTimeout:           defaultWriteTimeout,
		IdleTimeout:            defaultIdleTimeout,
		BackendTimeout:         defaultBackendTimeout,
		MaxHeaderBytes:         defaultMaxHeaderBytes,
		MaxResponseBytes:       defaultResponseMaxBytes,
	}
}

func loadGuardConfig() GuardConfig {
	c := defaultGuardConfig()
	c.ListenAddr = envString("GUARD_LISTEN", c.ListenAddr)
	c.BackendHTTP = envString("GUARD_BACKEND", c.BackendHTTP)
	c.DOHPath = envString("GUARD_DOH_PATH", c.DOHPath)
	c.HealthPath = envString("GUARD_HEALTH_PATH", c.HealthPath)
	c.ClientIPHeader = envHeader("GUARD_CLIENT_IP_HEADER", c.ClientIPHeader)
	c.MaxGlobalConns = envInt64("GLOBAL_CONN_LIMIT", envInt64("GUARD_MAX_GLOBAL_CONNS", c.MaxGlobalConns))
	c.MaxPerIPConns = envInt32("IP_CONN_LIMIT", c.MaxPerIPConns)
	c.MaxSourceStates = envInt("GUARD_MAX_IP_STATES", c.MaxSourceStates)
	c.MaxDNSMessage = envInt("DOH_MAX_BODY_BYTES", envInt("GUARD_MAX_DNS_MESSAGE", c.MaxDNSMessage))
	c.MaxQueriesPerConn = envUint32("GUARD_MAX_QUERIES_PER_CONN", c.MaxQueriesPerConn)
	c.MaxConcurrentReqs = envInt64("GUARD_MAX_CONCURRENT_REQS", c.MaxConcurrentReqs)
	c.MaxConcurrentReqsPerIP = envInt32("GUARD_MAX_CONCURRENT_REQS_PER_IP", c.MaxConcurrentReqsPerIP)
	c.MaxUpstreamConns = envInt("UPSTREAM_MAX_CONNS", c.MaxUpstreamConns)
	c.BackendDialTimeout = envDuration("GUARD_BACKEND_DIAL_TIMEOUT", c.BackendDialTimeout)
	c.StateIdle = envDuration("GUARD_STATE_IDLE", c.StateIdle)
	c.ReadHeaderTimeout = envDuration("GUARD_READ_HEADER_TIMEOUT", c.ReadHeaderTimeout)
	c.ReadTimeout = envDuration("GUARD_READ_TIMEOUT", c.ReadTimeout)
	c.WriteTimeout = envDuration("GUARD_WRITE_TIMEOUT", c.WriteTimeout)
	c.IdleTimeout = envDuration("GUARD_IDLE_TIMEOUT", c.IdleTimeout)
	c.BackendTimeout = envSecondsOrDuration("GUARD_RESPONSE_TIMEOUT", c.BackendTimeout)
	c.MaxHeaderBytes = envInt("GUARD_MAX_HEADER_BYTES", c.MaxHeaderBytes)
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
	if c.HealthPath == "" || c.HealthPath[0] != '/' || c.HealthPath == c.DOHPath {
		c.HealthPath = defaultHealthPath
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
	stateCap := c.MaxGlobalConns * 2
	if stateCap < 1 {
		stateCap = 2
	}
	if stateCap > 65535 {
		stateCap = 65535
	}
	if int64(c.MaxSourceStates) > stateCap {
		c.MaxSourceStates = int(stateCap)
	}
	if c.MaxDNSMessage < 64 || c.MaxDNSMessage > 65535 {
		c.MaxDNSMessage = defaultMaxDNSMessage
	}
	if c.MaxQueriesPerConn < 1 {
		c.MaxQueriesPerConn = defaultMaxQueriesConn
	}
	maxPlatformInt := int64(^uint(0) >> 1)
	if c.MaxConcurrentReqs < 1 || c.MaxConcurrentReqs > maxPlatformInt {
		c.MaxConcurrentReqs = defaultMaxRequests
	}
	if c.MaxConcurrentReqsPerIP < 1 {
		c.MaxConcurrentReqsPerIP = defaultMaxRequestsPerIP
	}
	if c.MaxUpstreamConns < 1 {
		c.MaxUpstreamConns = defaultMaxUpstreamConns
	}
	if c.MaxUpstreamConns > 65535 {
		c.MaxUpstreamConns = 65535
	}
	if int64(c.MaxConcurrentReqsPerIP) > c.MaxConcurrentReqs {
		c.MaxConcurrentReqsPerIP = int32(c.MaxConcurrentReqs)
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
	if c.BackendDialTimeout <= 0 {
		c.BackendDialTimeout = defaultBackendDial
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

func envInt(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || uint64(n) > uint64(^uint(0)>>1) {
		return fallback
	}
	return int(n)
}

func envInt32(name string, fallback int32) int32 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || n > int64(maxInt32) {
		return fallback
	}
	return int32(n)
}

func envHeader(name, fallback string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return http.CanonicalHeaderKey(fallback)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	key := http.CanonicalHeaderKey(v)
	if key == "" {
		return http.CanonicalHeaderKey(fallback)
	}
	return key
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

func envSecondsOrDuration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	if n, err := time.ParseDuration(v); err == nil {
		return n
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n > int64((time.Duration(1<<63-1))/time.Second) {
		return fallback
	}
	return time.Duration(n) * time.Second
}

type clientState struct {
	lastSeen time.Time
	conns    int32
	requests int32
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
	// Randomized hashing prevents an external client from deliberately concentrating
	// many source keys in one shard and forcing avoidable state churn.
	return maphash.String(t.seed, key)
}

func (t *sourceTable) shard(key string) *stateShard {
	return &t.shards[t.sourceHash(key)%uint64(t.shardCount)]
}

func (t *sourceTable) createLocked(shardIdx int, key string, now time.Time) *clientState {
	s := &t.shards[shardIdx]
	if len(s.clients) >= t.shardLimit[shardIdx] {
		var victimKey string
		var victim *clientState
		for k, candidate := range s.clients {
			if candidate.conns != 0 || candidate.requests != 0 {
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
	st := &clientState{lastSeen: now}
	s.clients[key] = st
	return st
}

func (t *sourceTable) admitRequest(key string, max int32, now time.Time) bool {
	if max < 1 {
		return false
	}
	shardIdx := t.sourceHash(key) % uint64(t.shardCount)
	s := &t.shards[shardIdx]
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.clients[key]
	if st == nil {
		st = t.createLocked(int(shardIdx), key, now)
		if st == nil {
			return false
		}
	}
	if st.requests >= max {
		return false
	}
	st.requests++
	st.lastSeen = now
	return true
}

func (t *sourceTable) releaseRequest(key string) {
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.clients[key]; st != nil && st.requests > 0 {
		st.requests--
		st.lastSeen = time.Now()
	}
}

func (t *sourceTable) admitConn(key string, max int32, now time.Time) bool {
	shardIdx := t.sourceHash(key) % uint64(t.shardCount)
	s := &t.shards[shardIdx]
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.clients[key]
	if st == nil {
		st = t.createLocked(int(shardIdx), key, now)
		if st == nil {
			return false
		}
	}
	st.lastSeen = now
	if st.conns >= max {
		return false
	}
	st.conns++
	return true
}

func (t *sourceTable) releaseConn(key string) {
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.clients[key]; st != nil && st.conns > 0 {
		st.conns--
		st.lastSeen = time.Now()
	}
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
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: cfg.BackendDialTimeout,
		}).DialContext,
		MaxConnsPerHost:        cfg.MaxUpstreamConns,
		MaxIdleConns:           cfg.MaxUpstreamConns,
		MaxIdleConnsPerHost:    cfg.MaxUpstreamConns,
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

func (g *Guard) releaseGlobalRequest() {
	g.activeReq.Add(-1)
}

func (g *Guard) releaseRequest(client string) {
	g.releaseGlobalRequest()
	g.states.releaseRequest(client)
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

// canonicalIPKey returns the per-client concurrency identity: IPv4 (and
// IPv4-mapped IPv6) addresses individually, IPv6 addresses by their /64 so a
// subscriber using privacy addresses in one delegated prefix shares one slot pool.
func canonicalIPKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func sourceIP(addr net.Addr) (net.IP, bool) {
	a, ok := addr.(*net.TCPAddr)
	if !ok || a.IP == nil {
		return nil, false
	}
	return a.IP, true
}

var cgnatPrefix = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isInternalIP reports whether ip is loopback, private, link-local or CGNAT
// space, i.e. an address that cannot be a directly connected Internet client.
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return cgnatPrefix.Contains(v4)
	}
	return false
}

func parseHeaderIP(token string) net.IP {
	token = strings.TrimSpace(token)
	if ip := net.ParseIP(token); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(token); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// clientIPFromHeader extracts the final trusted client identity from the
// forwarding header. For this deployment the final value is the only value
// accepted as certifiable; an internal, malformed, or missing final value is
// rejected instead of falling back to a shared proxy bucket.
func clientIPFromHeader(h http.Header, name string) (net.IP, bool) {
	values := h.Values(name)
	if len(values) == 0 {
		return nil, false
	}
	last := strings.TrimSpace(values[len(values)-1])
	parts := strings.Split(last, ",")
	if len(parts) == 0 {
		return nil, false
	}
	token := strings.TrimSpace(parts[len(parts)-1])
	ip := parseHeaderIP(token)
	if ip == nil || isInternalIP(ip) {
		return nil, false
	}
	return ip, true
}

type trackedConn struct {
	net.Conn
	guard    *Guard
	source   string
	trusted  bool // peer is a platform-internal proxy whose final forwarding value is required
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

// lastQuery reports whether the query just admitted by nextQuery was the final
// one allowed on this connection, so it can be answered and then closed cleanly.
func (c *trackedConn) lastQuery(max uint32) bool {
	return max != 0 && c.queries.Load() == max
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
		ip, ok := sourceIP(conn.RemoteAddr())
		if !ok {
			l.guard.releaseGlobal()
			_ = conn.Close()
			continue
		}
		source := canonicalIPKey(ip)
		// A platform-internal peer multiplexes many real users, so it is
		// bounded by the global cap instead of the per-source cap.
		trusted := l.guard.cfg.ClientIPHeader != "" && isInternalIP(ip)
		maxConns := l.guard.cfg.MaxPerIPConns
		if trusted {
			maxConns = int32(min(l.guard.cfg.MaxGlobalConns, maxInt32))
		}
		if !l.guard.states.admitConn(source, maxConns, time.Now()) {
			_ = conn.Close()
			l.guard.releaseGlobal()
			continue
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		return &trackedConn{Conn: conn, guard: l.guard, source: source, trusted: trusted}, nil
	}
}

func (l *guardedListener) Close() error {
	return l.inner.Close()
}

func (l *guardedListener) Addr() net.Addr { return l.inner.Addr() }

func (g *Guard) backendHealthy() bool {
	conn, err := net.DialTimeout("tcp", g.cfg.BackendHTTP, g.cfg.BackendDialTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (g *Guard) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, ok := r.Context().Value(connStateKey{}).(*trackedConn)
		if !ok || state == nil {
			return
		}
		if r.Context().Err() != nil {
			return
		}
		if !state.nextQuery(g.cfg.MaxQueriesPerConn) {
			g.reject(w, state, http.StatusTooManyRequests)
			return
		}
		// Behind the platform proxy every user shares the proxy's address, so the
		// real client is taken from the forwarding header (see clientIPFromHeader).
		client := state.source
		if state.trusted {
			ip, ok := clientIPFromHeader(r.Header, g.cfg.ClientIPHeader)
			if !ok {
				g.reject(w, state, http.StatusBadRequest)
				return
			}
			client = canonicalIPKey(ip)
		}
		if r.URL.Path == g.cfg.HealthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			if g.backendHealthy() {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}

		now := time.Now()
		if !g.acquireRequest() {
			g.reject(w, state, http.StatusTooManyRequests)
			return
		}
		if !g.states.admitRequest(client, g.cfg.MaxConcurrentReqsPerIP, now) {
			g.releaseGlobalRequest()
			g.reject(w, state, http.StatusTooManyRequests)
			return
		}
		defer g.releaseRequest(client)

		if r.URL.Path != g.cfg.DOHPath || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			// Keep GET / as a cheap platform wake/readiness compatibility response.
			// Real backend health is exposed separately at /healthz (GET/HEAD).
			if r.URL.Path == "/" && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				return
			}
			g.reject(w, state, http.StatusNotFound)
			return
		}
		if r.Header.Get("Upgrade") != "" {
			g.reject(w, state, http.StatusBadRequest)
			return
		}

		body, err := g.readDoHBody(r)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			g.reject(w, state, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), g.cfg.BackendTimeout)
		defer cancel()
		var requestBody io.Reader
		backendURI := g.cfg.DOHPath
		if r.Method == http.MethodPost {
			requestBody = bytes.NewReader(body)
		} else {
			backendURI += "?dns=" + base64.RawURLEncoding.EncodeToString(body)
		}
		backendReq, err := http.NewRequestWithContext(ctx, r.Method, "http://"+g.cfg.BackendHTTP+backendURI, requestBody)
		if err != nil {
			g.reject(w, state, http.StatusBadGateway)
			return
		}
		backendReq.Header.Set("X-Forwarded-For", client)
		if accept := r.Header.Get("Accept"); accept != "" {
			backendReq.Header.Set("Accept", accept)
		}
		if r.Method == http.MethodPost {
			backendReq.Header.Set("Content-Type", "application/dns-message")
		}

		resp, err := g.backend.Do(backendReq)
		if err != nil {
			// Browser navigation/network changes routinely cancel in-flight DoH
			// requests. That is a normal client lifecycle event, not an upstream
			// failure, so do not turn it into a synthetic 502 response.
			if r.Context().Err() != nil {
				return
			}
			g.reject(w, state, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.ContentLength > g.cfg.MaxResponseBytes {
			g.reject(w, state, http.StatusBadGateway)
			return
		}
		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, g.cfg.MaxResponseBytes+1))
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			g.reject(w, state, http.StatusBadGateway)
			return
		}
		if int64(len(responseBody)) > g.cfg.MaxResponseBytes {
			g.reject(w, state, http.StatusBadGateway)
			return
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && !validDNSResponse(body, responseBody) {
			g.reject(w, state, http.StatusBadGateway)
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
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.Header().Set("Content-Type", "application/dns-message")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		if state.lastQuery(g.cfg.MaxQueriesPerConn) {
			// Serve the final allowed query, then close, so the peer reconnects
			// instead of seeing a dropped request.
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(responseBody)
	})
}

func responseHopByHopHeaders(headers http.Header) map[string]struct{} {
	hopByHop := make(map[string]struct{}, 9)
	for _, name := range []string{
		"connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"content-length", // buffered response body gets a fresh exact length
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
			return nil, errors.New("missing dns query parameter")
		}
		body, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			body, err = base64.URLEncoding.DecodeString(encoded)
		}
		if err != nil || len(body) == 0 || len(body) > g.cfg.MaxDNSMessage {
			return nil, errors.New("invalid dns query size")
		}
		return body, nil
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil, errors.New("missing content type")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, errors.New("invalid content type")
	}
	if r.ContentLength > int64(g.cfg.MaxDNSMessage) {
		return nil, errors.New("oversized dns message")
	}
	limited := io.LimitReader(r.Body, int64(g.cfg.MaxDNSMessage)+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) == 0 || len(body) > g.cfg.MaxDNSMessage {
		return nil, errors.New("invalid dns message size")
	}
	return body, nil
}

func validDNSResponse(query, response []byte) bool {
	if len(response) < 12 || len(query) < 2 {
		return false
	}
	if response[0] != query[0] || response[1] != query[1] {
		return false
	}
	if response[2]&0x80 == 0 {
		return false
	}
	offset := 12
	counts := [4]int{
		int(binary.BigEndian.Uint16(response[4:6])),
		int(binary.BigEndian.Uint16(response[6:8])),
		int(binary.BigEndian.Uint16(response[8:10])),
		int(binary.BigEndian.Uint16(response[10:12])),
	}
	var ok bool
	for i := 0; i < counts[0]; i++ {
		offset, ok = skipDNSName(response, offset)
		if !ok || offset+4 > len(response) {
			return false
		}
		offset += 4
	}
	for section := 1; section < 4; section++ {
		for i := 0; i < counts[section]; i++ {
			offset, ok = skipDNSName(response, offset)
			if !ok || offset+10 > len(response) {
				return false
			}
			rdLength := int(binary.BigEndian.Uint16(response[offset+8 : offset+10]))
			offset += 10
			if rdLength > len(response)-offset {
				return false
			}
			offset += rdLength
		}
	}
	return offset == len(response)
}

func skipDNSName(message []byte, offset int) (int, bool) {
	if offset < 0 || offset >= len(message) {
		return 0, false
	}
	pos := offset
	jumps := 0
	for {
		if pos >= len(message) {
			return 0, false
		}
		length := message[pos]
		switch length & 0xc0 {
		case 0x00:
			pos++
			if length == 0 {
				if jumps > 0 {
					return offset, true
				}
				return pos, true
			}
			if length > 63 || int(length) > len(message)-pos {
				return 0, false
			}
			pos += int(length)
		case 0xc0:
			if pos+1 >= len(message) || jumps >= 128 {
				return 0, false
			}
			target := int(length&0x3f)<<8 | int(message[pos+1])
			if target >= len(message) {
				return 0, false
			}
			if jumps == 0 {
				offset = pos + 2
			}
			pos = target
			jumps++
		default:
			return 0, false
		}
	}
}

// reject refuses a request. Direct clients are silently disconnected for
// policy/concurrency/validation rejections, while backend failures are explicit 502s
// so strict DoH clients can retry or report the lookup failure.
func (g *Guard) reject(w http.ResponseWriter, state *trackedConn, status int) {
	if status == http.StatusBadGateway {
		w.WriteHeader(status)
		return
	}
	if state != nil && state.trusted {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		return
	}
	g.dropHTTP(w, status)
}

func (g *Guard) dropHTTP(w http.ResponseWriter, status int) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
		}
		return
	}
	// HTTP/2 has no Hijacker; returning the status lets the stream terminate
	// normally without emitting HTTP/1 hop-by-hop headers.
	w.WriteHeader(status)
}

type connStateKey struct{}

func envOverride(env []string, name, value string) []string {
	prefix := name + "="
	out := env[:0]
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			continue
		}
		out = append(out, item)
	}
	return append(out, prefix+value)
}

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

func runHealthcheck() error {
	conn, err := net.DialTimeout("udp", "127.0.0.1:5300", defaultBackendDial)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(defaultBackendDial))
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
		return errors.New("short healthcheck response")
	}
	if buf[0] != 0x12 || buf[1] != 0x34 {
		return errors.New("healthcheck transaction mismatch")
	}
	if buf[2]&0x80 == 0 || buf[3]&0x0f != 0 {
		return errors.New("healthcheck status failed")
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

	blocky := exec.Command("/app/blocky")
	blocky.Stdout = os.Stdout
	blocky.Stderr = os.Stderr
	// Keep the public guard's small heap target separate from Blocky's resolver
	// and cache heap. Both processes inherit the container environment, so give
	// the child its own explicit bounded target.
	blocky.Env = envOverride(os.Environ(), "GOMEMLIMIT", envString("BLOCKY_GOMEMLIMIT", defaultBlockyMemLimit))
	blocky.Env = envOverride(blocky.Env, "GOMAXPROCS", "1")
	if err := blocky.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start blocky:", err)
		stop()
		os.Exit(1)
	}

	type blockyResult struct {
		err        error
		unexpected bool
	}

	guardDone := make(chan error, 1)
	blockyDone := make(chan blockyResult, 1)
	var blockyMu sync.Mutex
	blockyTerminationRequested := false
	go func() { guardDone <- guard.Run(ctx) }()
	go func() {
		err := blocky.Wait()
		blockyMu.Lock()
		unexpected := !blockyTerminationRequested
		blockyMu.Unlock()
		blockyDone <- blockyResult{err: err, unexpected: unexpected}
	}()

	exitCode := 0
	blockyExited := false
	blockyResultSeen := false
	var br blockyResult
	select {
	case <-ctx.Done():
		// Context cancellation and a guard failure can become ready at the
		// same time. Wait for Guard first so a real guard failure cannot be
		// hidden by select choosing ctx.Done().
		if err := <-guardDone; err != nil {
			fmt.Fprintln(os.Stderr, "guard stopped:", err)
			exitCode = 1
		}
	case err := <-guardDone:
		if err != nil {
			fmt.Fprintln(os.Stderr, "guard stopped:", err)
			exitCode = 1
		}
		stop()
	case result := <-blockyDone:
		blockyExited = true
		blockyResultSeen = true
		br = result
		if result.unexpected {
			fmt.Fprintln(os.Stderr, "blocky exited:", result.err)
			exitCode = 1
		}
	}
	stop()

	if !blockyExited {
		// Hold the state lock while requesting termination. The Blocky waiter
		// takes the same lock after Wait returns, so an exit racing with the
		// shutdown request is classified consistently without touching
		// ProcessState from the supervisor.
		blockyMu.Lock()
		signalErr := blocky.Process.Signal(syscall.SIGTERM)
		if signalErr == nil {
			blockyTerminationRequested = true
		}
		blockyMu.Unlock()

		if signalErr != nil {
			fmt.Fprintln(os.Stderr, "stop blocky:", signalErr)
		}
		select {
		case result := <-blockyDone:
			blockyExited = true
			blockyResultSeen = true
			br = result
		case <-time.After(5 * time.Second):
			_ = blocky.Process.Kill()
			br = <-blockyDone
			blockyExited = true
			blockyResultSeen = true
		}
	}

	if blockyResultSeen && br.unexpected {
		fmt.Fprintln(os.Stderr, "blocky exited:", br.err)
		exitCode = 1
	}
	if !blockyExited {
		// Unreachable, kept as a defensive guard for future changes.
		exitCode = 1
	}
	os.Exit(exitCode)
}
