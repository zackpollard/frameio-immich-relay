// Package admin provides an optional, login-protected web panel for
// frameio-immich-relay. It is mounted on the relay's existing HTTP port
// under /admin, so the same tunnel that exposes /webhook to Frame.io also
// exposes the panel to a browser:
//
//	https://<public-host>/admin        dashboard (login required)
//	https://<public-host>/webhook      unchanged Frame.io webhook endpoint
//
// The panel can drive the Adobe IMS browser OAuth flow (so tokens.json can be
// created/renewed from any browser, not just a workstation), show live relay
// state, and trigger maintenance actions (reconcile, stuck-upload GC,
// webhook re-registration).
//
// Security model:
//   - Disabled entirely unless Config.Password is set.
//   - Password checked as salted SHA-256 with a per-process random salt,
//     constant-time compared. No external dependencies.
//   - Sessions are random 256-bit IDs in an in-memory map with TTL; cookie
//     is HttpOnly, SameSite=Lax (Lax so the Adobe OAuth redirect — a
//     top-level navigation — carries it), Secure when the request is HTTPS.
//   - Every state-changing POST requires a per-session CSRF token.
//   - Login attempts are throttled per source IP.
//   - Secrets (tokens, webhook secret, API keys) are never rendered.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
)

const (
	sessionCookie   = "frameio_admin"
	defaultTTL      = 12 * time.Hour
	maxLoginFails   = 10
	loginWindow     = 5 * time.Minute
	oauthFlowTTL    = 10 * time.Minute
	eventsMax       = 200
	recentEventsCap = 50

	// OAuthScopes must match what frameio-auth requests by default.
	OAuthScopes = "openid email profile offline_access additional_info.roles"
)

// Event is one line of relay activity shown on the dashboard.
type Event struct {
	At  time.Time `json:"at"`
	Msg string    `json:"msg"`
}

// Status is a point-in-time snapshot of the relay configuration + runtime.
// It must never contain secrets.
type Status struct {
	Version        string        `json:"version"`
	StartedAt      time.Time     `json:"started_at"`
	Uptime         string        `json:"uptime"`
	Account        string        `json:"account"`
	Workspace      string        `json:"workspace"`
	Folder         string        `json:"folder"`
	PublicURL      string        `json:"public_url"` // webhook URL; "" = polling-only
	AdminURL       string        `json:"admin_url"`  // e.g. https://host/admin
	PollingOnly    bool          `json:"polling_only"`
	ImmichURL      string        `json:"immich_url"` // "" = disabled
	PollInterval   time.Duration `json:"poll_interval"`
	StuckTimeout   time.Duration `json:"stuck_timeout"`
	DryRun         bool          `json:"dry_run"`
	Inflight       int           `json:"inflight"`
	WebhookID      string        `json:"webhook_id"`
	WebhookTarget  string        `json:"webhook_target"`
	TokensPath     string        `json:"tokens_path"`
	StateFile      string        `json:"state_file"`
	OutDir         string        `json:"out_dir"`
	AuthName       string        `json:"auth_name"` // cached from startup
	TokenExpiry    time.Time     `json:"token_expiry"`
	HasRefresh     bool          `json:"has_refresh"`
	AdminEnabled   bool          `json:"admin_enabled"`
	OAuthAvailable bool          `json:"oauth_available"` // public HTTPS origin + client creds present
}

// Backend is everything the admin panel needs from the relay process.
// Implemented by the relay in cmd/frameio-relay.
type Backend interface {
	Status() Status
	Events(n int) []Event
	AuthCheck(ctx context.Context) (name string, err error)
	ReconcileNow()
	ReapStuckNow()
	RegisterWebhook(ctx context.Context) (id string, err error)
	DeleteWebhook(ctx context.Context) error
	ListWebhooks(ctx context.Context) ([]frameio.Webhook, error)
	ReloadTokens() error
	ClientCredentials() (clientID, clientSecret string, ok bool)
	ExchangeOAuthCode(ctx context.Context, code, redirectURI string) error
	DownloadStats() (files int, bytes int64)
	StateView() map[string]any
}

// Config controls the admin panel.
type Config struct {
	Password     string        // admin login password; empty disables the panel
	SessionTTL   time.Duration // zero → 12h
	PublicOrigin string        // e.g. "https://host.ts.net" (no trailing path); empty if polling-only
	Version      string
}

type session struct {
	id      string
	csrf    string
	expires time.Time
}

type oauthFlow struct {
	sessionID   string
	redirectURI string
	created     time.Time
}

// Server is the admin panel HTTP handler.
type Server struct {
	cfg     Config
	backend Backend

	pwSalt [16]byte
	pwHash [32]byte

	mu       sync.Mutex
	sessions map[string]*session
	pending  map[string]*oauthFlow
	fails    map[string][]time.Time

	tmpl *template.Template
}

// New builds the admin panel. Returns an error if the password is empty or
// the backend is nil — callers should treat that as "admin disabled" and
// simply not mount the handler.
func New(cfg Config, b Backend) (*Server, error) {
	if cfg.Password == "" {
		return nil, errors.New("admin: empty password (panel disabled)")
	}
	if b == nil {
		return nil, errors.New("admin: nil backend")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultTTL
	}
	tmpl, err := template.New("").ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("admin: parse templates: %w", err)
	}
	s := &Server{
		cfg:      cfg,
		backend:  b,
		sessions: map[string]*session{},
		pending:  map[string]*oauthFlow{},
		fails:    map[string][]time.Time{},
		tmpl:     tmpl,
	}
	if _, err := rand.Read(s.pwSalt[:]); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(s.pwSalt[:], []byte(cfg.Password)...))
	s.pwHash = sum
	return s, nil
}

// Handler returns the root mux with every /admin route registered. Mount it
// on the relay's existing HTTP server alongside /webhook.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.Handler) http.Handler { return s.requireAuth(h) }
	authCSRF := func(h http.Handler) http.Handler { return s.requireAuth(s.requireCSRF(h)) }
	mux.HandleFunc("GET /admin/login", s.handleLoginForm)
	mux.HandleFunc("POST /admin/login", s.handleLogin)
	mux.Handle("POST /admin/logout", authCSRF(http.HandlerFunc(s.handleLogout)))
	mux.Handle("POST /admin/oauth/start", authCSRF(http.HandlerFunc(s.handleOAuthStart)))
	mux.Handle("GET /admin/oauth/callback", auth(http.HandlerFunc(s.handleOAuthCallback)))
	mux.Handle("GET /admin/api/status", auth(http.HandlerFunc(s.handleAPIStatus)))
	mux.Handle("GET /admin/state", auth(http.HandlerFunc(s.handleState)))
	mux.Handle("POST /admin/reconcile", authCSRF(http.HandlerFunc(s.handleReconcile)))
	mux.Handle("POST /admin/reap-stuck", authCSRF(http.HandlerFunc(s.handleReapStuck)))
	mux.Handle("POST /admin/webhook/register", authCSRF(http.HandlerFunc(s.handleWebhookRegister)))
	mux.Handle("POST /admin/webhook/delete", authCSRF(http.HandlerFunc(s.handleWebhookDelete)))
	mux.Handle("POST /admin/tokens/reload", authCSRF(http.HandlerFunc(s.handleTokensReload)))
	mux.Handle("POST /admin/auth/check", authCSRF(http.HandlerFunc(s.handleAuthCheck)))
	mux.Handle("GET /admin", auth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /admin/", auth(http.HandlerFunc(s.handleDashboard)))
	return mux
}

// --- auth plumbing --------------------------------------------------------

type ctxKey int

const ctxSession ctxKey = iota

func (s *Server) hashPassword(pw string) [32]byte {
	return sha256.Sum256(append(s.pwSalt[:], []byte(pw)...))
}

func (s *Server) checkPassword(pw string) bool {
	h := s.hashPassword(pw)
	return subtle.ConstantTimeCompare(h[:], s.pwHash[:]) == 1
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if ip, _, ok := strings.Cut(fwd, ","); ok {
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginThrottled reports whether this IP has exceeded the failed-login budget.
func (s *Server) loginThrottled(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-loginWindow)
	kept := s.fails[ip][:0]
	for _, t := range s.fails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.fails[ip] = kept
	return len(kept) >= maxLoginFails
}

func (s *Server) recordFail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails[ip] = append(s.fails[ip], time.Now())
}

func (s *Server) createSession() (*session, error) {
	id, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	sess := &session{id: id, csrf: csrf, expires: time.Now().Add(s.cfg.SessionTTL)}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

func (s *Server) session(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return nil
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	return sess
}

func (s *Server) dropSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// requireAuth redirects unauthenticated HTML requests to the login page and
// rejects API requests with 401.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.session(r)
		if sess == nil {
			if strings.HasPrefix(r.URL.Path, "/admin/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/admin/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxSession, sess)))
	})
}

// requireCSRF validates the per-session CSRF token on POST forms.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		sess, _ := r.Context().Value(ctxSession).(*session)
		if sess == nil || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.csrf)) != 1 {
			http.Error(w, "bad CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sessionFrom(r *http.Request) *session {
	sess, _ := r.Context().Value(ctxSession).(*session)
	return sess
}

// --- login ----------------------------------------------------------------

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.session(r) != nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", loginPage{
		Title: "Sign in",
		Error: r.URL.Query().Get("error"),
		Next:  r.URL.Query().Get("next"),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ip := clientIP(r)
	if s.loginThrottled(ip) {
		http.Error(w, "too many failed attempts; try again later", http.StatusTooManyRequests)
		return
	}
	pw := r.FormValue("password")
	if !s.checkPassword(pw) {
		s.recordFail(ip)
		http.Redirect(w, r, "/admin/login?error=invalid+password", http.StatusSeeOther)
		return
	}
	sess, err := s.createSession()
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.id,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode, // Lax: the Adobe OAuth redirect is a top-level GET navigation
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
	next := r.FormValue("next")
	if next == "" || !strings.HasPrefix(next, "/admin") {
		next = "/admin"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionFrom(r); sess != nil {
		s.dropSession(sess.id)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/admin",
		HttpOnly: true, MaxAge: -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
