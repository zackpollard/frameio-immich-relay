package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
)

type loginPage struct {
	Title string
	Error string
	Next  string
}

type dashPage struct {
	Title     string
	Status    Status
	Events    []Event
	Downloads struct {
		Files int   `json:"files"`
		Bytes int64 `json:"bytes"`
	}
	Webhooks   []frameio.Webhook
	WebhookErr string
	Flash      string // "ok" | "error"
	FlashMsg   string
	CSRF       string
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func redirectFlash(w http.ResponseWriter, r *http.Request, kind, msg string) {
	q := url.Values{}
	if kind != "" {
		q.Set("flash", kind)
		q.Set("msg", msg)
	}
	http.Redirect(w, r, "/admin?"+q.Encode(), http.StatusSeeOther)
}

// --- dashboard + API ------------------------------------------------------

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	st := s.backend.Status()
	files, bytes := s.backend.DownloadStats()
	page := dashPage{
		Title:  "Dashboard",
		Status: st,
		Events: s.backend.Events(recentEventsCap),
		CSRF:   sessionFrom(r).csrf,
		Flash:  r.URL.Query().Get("flash"),
	}
	page.FlashMsg = r.URL.Query().Get("msg")
	page.Downloads.Files = files
	page.Downloads.Bytes = bytes
	if st.Workspace != "" {
		hooks, err := s.backend.ListWebhooks(r.Context())
		if err != nil {
			page.WebhookErr = err.Error()
		} else {
			page.Webhooks = hooks
		}
	}
	s.render(w, "dashboard.html", page)
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	files, bytes := s.backend.DownloadStats()
	st := s.backend.Status()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    st,
		"events":    s.backend.Events(30),
		"downloads": map[string]any{"files": files, "bytes": bytes},
	})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(s.backend.StateView())
}

// --- actions (all POST + CSRF) --------------------------------------------

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	s.backend.ReconcileNow()
	redirectFlash(w, r, "ok", "reconcile pass started in the background")
}

func (s *Server) handleReapStuck(w http.ResponseWriter, r *http.Request) {
	s.backend.ReapStuckNow()
	redirectFlash(w, r, "ok", "stuck-upload garbage collection started in the background")
}

func (s *Server) handleWebhookRegister(w http.ResponseWriter, r *http.Request) {
	id, err := s.backend.RegisterWebhook(r.Context())
	if err != nil {
		redirectFlash(w, r, "error", "webhook registration failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "ok", "webhook registered: "+id)
}

func (s *Server) handleWebhookDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.DeleteWebhook(r.Context()); err != nil {
		redirectFlash(w, r, "error", "webhook delete failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "ok", "webhook deleted; relay falls back to polling")
}

func (s *Server) handleTokensReload(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.ReloadTokens(); err != nil {
		redirectFlash(w, r, "error", "token reload failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "ok", "tokens reloaded from disk")
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	name, err := s.backend.AuthCheck(ctx)
	if err != nil {
		redirectFlash(w, r, "error", "auth check failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "ok", fmt.Sprintf("authenticated as %s", name))
}

// --- browser OAuth flow -----------------------------------------------------
//
// POST /admin/oauth/start generates a state nonce, remembers the flow, and
// redirects the browser to Adobe IMS. Adobe redirects back to
//   <public-origin>/admin/oauth/callback?code=...&state=...
// which must be registered as a redirect URI in the Adobe Developer Console
// project. The callback exchanges the code (on a path-less throwaway
// TokenStore so the public callback URL is never persisted as redirect_uri)
// and adopts the resulting tokens into the live store.

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	clientID, _, ok := s.backend.ClientCredentials()
	if !ok {
		redirectFlash(w, r, "error", "no Adobe client credentials in tokens.json — run frameio-auth once on a workstation first")
		return
	}
	origin := s.cfg.PublicOrigin
	if origin == "" {
		redirectFlash(w, r, "error", "FRAMEIO_PUBLIC_URL is not set — the browser OAuth flow needs the public HTTPS URL (set it, or run frameio-auth on a workstation)")
		return
	}
	state, err := randomHex(32)
	if err != nil {
		http.Error(w, "rng error", http.StatusInternalServerError)
		return
	}
	redirectURI := origin + "/admin/oauth/callback"
	probe := &frameio.TokenStore{ClientID: clientID, RedirectURI: redirectURI}
	authURL := probe.AuthorizeURL(state, []string{
		"openid", "email", "profile", "offline_access", "additional_info.roles",
	})
	s.mu.Lock()
	s.pending[state] = &oauthFlow{sessionID: sess.id, redirectURI: redirectURI, created: time.Now()}
	s.mu.Unlock()
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		redirectFlash(w, r, "error", "Adobe OAuth error: "+e+" "+q.Get("error_description"))
		return
	}
	state, code := q.Get("state"), q.Get("code")
	sess := sessionFrom(r)

	s.mu.Lock()
	flow, ok := s.pending[state]
	if ok {
		delete(s.pending, state)
	}
	s.mu.Unlock()
	if !ok || flow.sessionID != sess.id || time.Since(flow.created) > oauthFlowTTL {
		redirectFlash(w, r, "error", "OAuth state mismatch or expired — restart the login from the dashboard")
		return
	}
	if code == "" {
		redirectFlash(w, r, "error", "OAuth callback carried no code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.backend.ExchangeOAuthCode(ctx, code, flow.redirectURI); err != nil {
		redirectFlash(w, r, "error", "token exchange failed: "+err.Error())
		return
	}
	name, _ := s.backend.AuthCheck(ctx)
	redirectFlash(w, r, "ok", "Frame.io authentication saved (authenticated as "+name+")")
}
