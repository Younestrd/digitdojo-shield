package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"digitdojo-shield/internal/blacklist"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/events"
	"digitdojo-shield/internal/whitelist"
)

// Server exposes the management API for the shield daemon.
type Server struct {
	cfg             config.Config
	blacklist       *blacklist.Manager
	whitelist       *whitelist.Manager
	statsProvider   func() RuntimeStats
	addBlacklist    func(string) error
	addWhitelist    func(string) error
	removeBlacklist func(string) error
	subscribe       func(func(events.Event)) func()
	limiter         *rateLimiter
	server          *http.Server
	mu              sync.Mutex
}

// RuntimeStats is the shared daemon state exposed by the management API.
type RuntimeStats struct {
	Signals          int    `json:"signals"`
	Blocked          int    `json:"blocked"`
	PacketsPerSecond int    `json:"packets_per_second"`
	BandwidthMbps    int    `json:"bandwidth_mbps"`
	AttackStatus     string `json:"attack_status"`
	FirewallBackend  string `json:"firewall_backend"`
	FirewallEnforced bool   `json:"firewall_enforced"`
}

type ipRequest struct {
	IP string `json:"ip"`
}

// Dependencies connects the API to the application's shared state.
type Dependencies struct {
	Blacklist       *blacklist.Manager
	Whitelist       *whitelist.Manager
	Stats           func() RuntimeStats
	AddBlacklist    func(string) error
	AddWhitelist    func(string) error
	RemoveBlacklist func(string) error
	Subscribe       func(func(events.Event)) func()
}

// ErrEnforcementUnavailable indicates that a requested firewall mutation cannot
// yet be applied safely. The API reports it as service unavailable.
var ErrEnforcementUnavailable = errors.New("firewall enforcement is unavailable")

// NewServer creates a new API server instance.
func NewServer(cfg config.Config) *Server {
	blacklistManager := blacklist.NewManager()
	whitelistManager := whitelist.NewManager()
	return newServer(cfg, Dependencies{
		Blacklist: blacklistManager,
		Whitelist: whitelistManager,
		AddBlacklist: func(ip string) error {
			return blacklistManager.Add(cfg, ip)
		},
		AddWhitelist: func(ip string) error {
			return whitelistManager.Add(cfg, ip)
		},
		RemoveBlacklist: blacklistManager.Remove,
	})
}

// NewServerWithDependencies creates an API connected to runtime-owned state.
func NewServerWithDependencies(cfg config.Config, deps Dependencies) (*Server, error) {
	if deps.Blacklist == nil || deps.Whitelist == nil {
		return nil, fmt.Errorf("shared blacklist and whitelist are required")
	}
	if deps.AddBlacklist == nil || deps.AddWhitelist == nil || deps.RemoveBlacklist == nil {
		return nil, fmt.Errorf("shared list mutation handlers are required")
	}
	return newServer(cfg, deps), nil
}

func newServer(cfg config.Config, deps Dependencies) *Server {
	rateLimit := cfg.API.RateLimit
	if rateLimit <= 0 {
		rateLimit = 30
	}
	burst := cfg.API.RateBurst
	if burst <= 0 {
		burst = 60
	}
	return &Server{
		cfg:             cfg,
		blacklist:       deps.Blacklist,
		whitelist:       deps.Whitelist,
		statsProvider:   deps.Stats,
		addBlacklist:    deps.AddBlacklist,
		addWhitelist:    deps.AddWhitelist,
		removeBlacklist: deps.RemoveBlacklist,
		subscribe:       deps.Subscribe,
		limiter:         newRateLimiter(rateLimit, burst),
	}
}

// Handler returns an HTTP handler with authentication and rate limiting applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("/blocked", s.authMiddleware(s.handleBlocked))
	mux.HandleFunc("/blacklist", s.authMiddleware(s.handleBlacklist))
	mux.HandleFunc("/whitelist", s.authMiddleware(s.handleWhitelist))
	mux.HandleFunc("/unban", s.authMiddleware(s.handleUnban))
	mux.HandleFunc("/events", s.authMiddleware(s.handleEvents))
	return mux
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.subscribe == nil {
		s.writeJSONError(w, http.StatusServiceUnavailable, "event streaming is unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeJSONError(w, http.StatusInternalServerError, "streaming is unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	eventCh := make(chan events.Event, 32)
	unsubscribe := s.subscribe(func(event events.Event) {
		select {
		case eventCh <- event:
		default:
		}
	})
	defer unsubscribe()
	fmt.Fprint(w, "retry: 5000\n\n")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-eventCh:
			payload, err := json.Marshal(struct {
				Type    string            `json:"type"`
				Payload map[string]string `json:"payload"`
			}{Type: event.Type, Payload: event.Payload})
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\nid: %s\n\n", event.Type, payload, strconv.FormatInt(time.Now().UnixNano(), 10))
			flusher.Flush()
		}
	}
}

// Serve listens on the configured bind address.
func (s *Server) Serve(addr string) error {
	if addr == "" {
		addr = s.cfg.API.BindAddress
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.ServeListener(listener)
}

// ServeListener serves an already-bound listener, allowing startup failures to
// be handled synchronously by the application lifecycle.
func (s *Server) ServeListener(listener net.Listener) error {
	errors, err := s.StartListener(listener)
	if err != nil {
		return err
	}
	return <-errors
}

// StartListener registers the server synchronously and serves in the
// background. This removes the startup/shutdown race around listener ownership.
func (s *Server) StartListener(listener net.Listener) (<-chan error, error) {
	if listener == nil {
		return nil, fmt.Errorf("API listener is required")
	}
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	s.mu.Lock()
	if s.server != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("API server is already running")
	}
	s.server = server
	s.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		s.mu.Lock()
		if s.server == server {
			s.server = nil
		}
		s.mu.Unlock()
		result <- err
		close(result)
	}()
	return result, nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	if server == nil {
		return nil
	}
	return server.Shutdown(ctx)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	stats := RuntimeStats{Blocked: s.blacklist.ListLen(), AttackStatus: "starting"}
	if s.statsProvider != nil {
		stats = s.statsProvider()
	}
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.API.Enabled {
			next(w, r)
			return
		}
		if !s.authenticate(r) {
			s.writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !s.limiter.allow(clientKey(r)) {
			s.writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

func (s *Server) authenticate(r *http.Request) bool {
	if !s.cfg.API.Enabled {
		return true
	}
	token := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if token == "" {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}
	}
	if token == "" {
		return false
	}
	expected := []byte(s.cfg.API.Token)
	provided := []byte(token)
	return subtle.ConstantTimeCompare(expected, provided) == 1
}

func (s *Server) writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

type rateLimiter struct {
	mu        sync.Mutex
	limit     float64
	burst     float64
	buckets   map[string]*tokenBucket
	lastSweep time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(limit, burst int) *rateLimiter {
	if limit <= 0 {
		limit = 30
	}
	if burst <= 0 {
		burst = 60
	}
	return &rateLimiter{limit: float64(limit), burst: float64(burst), buckets: make(map[string]*tokenBucket), lastSweep: time.Now()}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if now.Sub(rl.lastSweep) >= time.Minute {
		for bucketKey, bucket := range rl.buckets {
			if now.Sub(bucket.last) >= 10*time.Minute {
				delete(rl.buckets, bucketKey)
			}
		}
		rl.lastSweep = now
	}
	bucket, ok := rl.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.last = now
	bucket.tokens += elapsed * rl.limit
	if bucket.tokens > rl.burst {
		bucket.tokens = rl.burst
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Blocked  []string `json:"blocked"`
		Enforced bool     `json:"enforced"`
	}{Blocked: s.blacklist.List(), Enforced: false})
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req ipRequest
	if err := s.decodeJSONBody(r, &req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.addBlacklist(req.IP); err != nil {
		s.writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprint(w, "ok")
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req ipRequest
	if err := s.decodeJSONBody(r, &req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.addWhitelist(req.IP); err != nil {
		s.writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprint(w, "ok")
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req ipRequest
	if err := s.decodeJSONBody(r, &req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.removeBlacklist(req.IP); err != nil {
		s.writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}

func (s *Server) writeMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrEnforcementUnavailable) {
		s.writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.writeJSONError(w, http.StatusBadRequest, err.Error())
}

func (s *Server) decodeJSONBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("request body is empty")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}
	return nil
}

func clientKey(r *http.Request) string {
	host := r.RemoteAddr
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSpace(host)
}
