package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
)

// fakeBackend implements Backend with in-memory state.
type fakeBackend struct {
	mu          sync.Mutex
	status      Status
	events      []Event
	reconciled  int
	reaped      int
	registered  string
	deletedHook bool
	reloaded    bool
	exchanged   string
	authName    string
	authErr     error
	credsOK     bool
}

func (f *fakeBackend) Status() Status { return f.status }
func (f *fakeBackend) Events(n int) []Event {
	if n > len(f.events) {
		n = len(f.events)
	}
	return f.events[len(f.events)-n:]
}
func (f *fakeBackend) AuthCheck(ctx context.Context) (string, error) { return f.authName, f.authErr }
func (f *fakeBackend) ReconcileNow()                                 { f.mu.Lock(); f.reconciled++; f.mu.Unlock() }
func (f *fakeBackend) ReapStuckNow()                                 { f.mu.Lock(); f.reaped++; f.mu.Unlock() }
func (f *fakeBackend) RegisterWebhook(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered = "wh-123"
	return f.registered, nil
}
func (f *fakeBackend) DeleteWebhook(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedHook = true
	return nil
}
func (f *fakeBackend) ListWebhooks(ctx context.Context) ([]frameio.Webhook, error) {
	return []frameio.Webhook{{ID: "wh-123", URL: "https://x.example/webhook", Events: []string{"file.upload.completed"}}}, nil
}
func (f *fakeBackend) ReloadTokens() error { f.mu.Lock(); f.reloaded = true; f.mu.Unlock(); return nil }
func (f *fakeBackend) ClientCredentials() (string, string, bool) {
	if f.credsOK {
		return "cid", "csecret", true
	}
	return "", "", false
}
func (f *fakeBackend) ExchangeOAuthCode(ctx context.Context, code, redirectURI string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exchanged = code + "@" + redirectURI
	return nil
}
func (f *fakeBackend) DownloadStats() (int, int64) { return 3, 1234 }
func (f *fakeBackend) StateView() map[string]any {
	return map[string]any{"webhook_id": "wh-123", "webhook_secret_set": true}
}

func newTestServer(t *testing.T, cfg Config, b Backend) *Server {
	t.Helper()
	if cfg.Password == "" {
		cfg.Password = "hunter2"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = time.Hour
	}
	s, err := New(cfg, b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func testStatus() Status {
	return Status{
		Version: "test", StartedAt: time.Now().Add(-time.Minute), Uptime: "1m0s",
		Account: "acc", Workspace: "ws", Folder: "fol",
		PublicURL: "https://relay.example.com/webhook", AdminURL: "https://relay.example.com/admin",
		PollInterval: 300 * time.Second, StuckTimeout: time.Hour,
		TokensPath: "/data/tokens.json", StateFile: "/data/relay-state.json", OutDir: "/downloads",
		AuthName: "Zack", TokenExpiry: time.Now().Add(time.Hour), HasRefresh: true,
		WebhookID: "wh-123", WebhookTarget: "https://relay.example.com/webhook",
		AdminEnabled: true, OAuthAvailable: true,
	}
}

func doReq(t *testing.T, h http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// loginAndGetCookie performs a successful login and returns the session cookie.
func loginAndGetCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	rec := doReq(t, h, "POST", "/admin/login", url.Values{"password": {"hunter2"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d, want 303 (body=%q)", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("login: no session cookie set")
	return nil
}

func TestNewRequiresPassword(t *testing.T) {
	if _, err := New(Config{Password: ""}, &fakeBackend{}); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestDashboardRequiresAuth(t *testing.T) {
	s := newTestServer(t, Config{}, &fakeBackend{status: testStatus()})
	rec := doReq(t, s.Handler(), "GET", "/admin", nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/admin/login") {
		t.Fatalf("unauthenticated /admin: got %d loc=%q, want 303 to login", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginWrongPassword(t *testing.T) {
	s := newTestServer(t, Config{}, &fakeBackend{})
	rec := doReq(t, s.Handler(), "POST", "/admin/login", url.Values{"password": {"nope"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303 back to login", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("expected error flash in redirect, got %q", rec.Header().Get("Location"))
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set on failed login")
	}
}

func TestLoginThrottle(t *testing.T) {
	s := newTestServer(t, Config{}, &fakeBackend{})
	for i := 0; i < maxLoginFails; i++ {
		rec := doReq(t, s.Handler(), "POST", "/admin/login", url.Values{"password": {"nope"}})
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("throttled too early at attempt %d", i+1)
		}
	}
	rec := doReq(t, s.Handler(), "POST", "/admin/login", url.Values{"password": {"nope"}})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", maxLoginFails, rec.Code)
	}
}

func TestLoginSuccessAndDashboard(t *testing.T) {
	b := &fakeBackend{status: testStatus(), events: []Event{{At: time.Now(), Msg: "hello"}}}
	s := newTestServer(t, Config{}, b)
	cookie := loginAndGetCookie(t, s.Handler())

	rec := doReq(t, s.Handler(), "GET", "/admin", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"frameio-relay admin", "Zack", "wh-123", "hello", "Re-authenticate with Frame.io"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard body missing %q", want)
		}
	}
	// Secrets must never appear.
	if strings.Contains(body, "csecret") {
		t.Error("dashboard leaked client secret")
	}
	// Cookie flags.
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax (OAuth redirect is a top-level GET)", cookie.SameSite)
	}
}

func TestAPISatusRequiresAuth(t *testing.T) {
	s := newTestServer(t, Config{}, &fakeBackend{status: testStatus()})
	rec := doReq(t, s.Handler(), "GET", "/admin/api/status", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("api without session: got %d, want 401", rec.Code)
	}
	cookie := loginAndGetCookie(t, s.Handler())
	rec = doReq(t, s.Handler(), "GET", "/admin/api/status", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("api with session: got %d, want 200", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("api json: %v", err)
	}
	if _, ok := out["status"]; !ok {
		t.Error("api response missing status")
	}
}

func TestCSRFRequiredOnActions(t *testing.T) {
	b := &fakeBackend{status: testStatus()}
	s := newTestServer(t, Config{}, b)
	cookie := loginAndGetCookie(t, s.Handler())

	// No CSRF token → 403, backend untouched.
	rec := doReq(t, s.Handler(), "POST", "/admin/reconcile", url.Values{}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without csrf: got %d, want 403", rec.Code)
	}
	if b.reconciled != 0 {
		t.Fatal("backend action ran despite missing CSRF token")
	}

	// Fetch dashboard to learn the session's CSRF token from the rendered form.
	rec = doReq(t, s.Handler(), "GET", "/admin", nil, cookie)
	body := rec.Body.String()
	marker := `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("dashboard has no csrf field")
	}
	csrf := body[i+len(marker):]
	csrf = csrf[:strings.Index(csrf, `"`)]

	rec = doReq(t, s.Handler(), "POST", "/admin/reconcile", url.Values{"csrf": {csrf}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST with csrf: got %d, want 303", rec.Code)
	}
	if b.reconciled != 1 {
		t.Fatal("backend action did not run with valid CSRF token")
	}
}

func TestOAuthStartRequiresPublicOriginAndCreds(t *testing.T) {
	b := &fakeBackend{status: testStatus(), credsOK: true}
	s := newTestServer(t, Config{PublicOrigin: ""}, b) // no public origin
	cookie := loginAndGetCookie(t, s.Handler())
	csrf := csrfFor(t, s, cookie)

	rec := doReq(t, s.Handler(), "POST", "/admin/oauth/start", url.Values{"csrf": {csrf}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=error") {
		t.Fatalf("expected error flash for missing public origin, got %q", loc)
	}
}

func TestOAuthStartRedirectsToIMS(t *testing.T) {
	b := &fakeBackend{status: testStatus(), credsOK: true}
	s := newTestServer(t, Config{PublicOrigin: "https://relay.example.com"}, b)
	cookie := loginAndGetCookie(t, s.Handler())
	csrf := csrfFor(t, s, cookie)

	rec := doReq(t, s.Handler(), "POST", "/admin/oauth/start", url.Values{"csrf": {csrf}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://ims-na1.adobelogin.com/ims/authorize/v2") {
		t.Fatalf("expected redirect to IMS authorize, got %q", loc)
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id = %q, want cid", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://relay.example.com/admin/oauth/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("state") == "" {
		t.Error("missing state param")
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Errorf("scope missing offline_access: %q", q.Get("scope"))
	}

	// Callback with the issued state + a code → backend exchange runs.
	state := q.Get("state")
	rec = doReq(t, s.Handler(), "GET", "/admin/oauth/callback?code=abc&state="+state, nil, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback: got %d, want 303", rec.Code)
	}
	if b.exchanged != "abc@https://relay.example.com/admin/oauth/callback" {
		t.Errorf("exchange got %q", b.exchanged)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=ok") {
		t.Errorf("callback should flash ok, got %q", loc)
	}
}

func TestOAuthCallbackRejectsBadState(t *testing.T) {
	b := &fakeBackend{status: testStatus(), credsOK: true}
	s := newTestServer(t, Config{PublicOrigin: "https://relay.example.com"}, b)
	cookie := loginAndGetCookie(t, s.Handler())
	rec := doReq(t, s.Handler(), "GET", "/admin/oauth/callback?code=abc&state=bogus", nil, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=error") {
		t.Errorf("expected error flash for bad state, got %q", loc)
	}
	if b.exchanged != "" {
		t.Error("exchange must not run on bad state")
	}
}

func TestStateViewMasksSecret(t *testing.T) {
	b := &fakeBackend{status: testStatus()}
	s := newTestServer(t, Config{}, b)
	cookie := loginAndGetCookie(t, s.Handler())
	rec := doReq(t, s.Handler(), "GET", "/admin/state", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret\":\"") && !strings.Contains(body, "secret_set") {
		t.Errorf("state view must not leak the secret value: %s", body)
	}
}

func csrfFor(t *testing.T, s *Server, cookie *http.Cookie) string {
	t.Helper()
	rec := doReq(t, s.Handler(), "GET", "/admin", nil, cookie)
	body := rec.Body.String()
	marker := `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no csrf field on dashboard")
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}
