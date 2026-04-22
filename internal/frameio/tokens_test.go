package frameio

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenStore_SaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	orig := &TokenStore{
		Path:         path,
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURI:  "https://localhost:12345/callback",
		Access:       "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		Scope:        "openid",
	}
	if err := orig.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClientID != orig.ClientID ||
		loaded.Access != orig.Access ||
		loaded.RefreshToken != orig.RefreshToken ||
		!loaded.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("roundtrip mismatch:\nwant %+v\ngot  %+v", orig, loaded)
	}

	// file should be 0600
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("tokens file perm: got %o want 0600", info.Mode().Perm())
	}
}

func TestTokenStore_LoadMissingReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	s, err := LoadTokenStore(path)
	if err != nil {
		t.Fatalf("should not error on missing file: %v", err)
	}
	if s.Access != "" || s.RefreshToken != "" {
		t.Error("expected empty store")
	}
	if s.Path != path {
		t.Errorf("path not set: %q", s.Path)
	}
}

func TestTokenStore_AuthorizeURL(t *testing.T) {
	s := &TokenStore{
		ClientID:    "cid",
		RedirectURI: "https://localhost:12345/callback",
	}
	u := s.AuthorizeURL("state-abc", []string{"openid", "email", "additional_info.roles"})

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, IMSAuthorizeURL+"?") {
		t.Errorf("unexpected prefix: %s", u)
	}
	q := parsed.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id: %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://localhost:12345/callback" {
		t.Errorf("redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: %q", q.Get("response_type"))
	}
	if q.Get("state") != "state-abc" {
		t.Errorf("state: %q", q.Get("state"))
	}
	if q.Get("scope") != "openid email additional_info.roles" {
		t.Errorf("scope: %q", q.Get("scope"))
	}
}

// Swap the IMS token endpoint for the duration of a test.
func withIMS(t *testing.T, srv *httptest.Server) func() {
	t.Helper()
	orig := imsTokenURL
	imsTokenURL = srv.URL
	return func() { imsTokenURL = orig }
}

func TestTokenStore_ExchangeCode(t *testing.T) {
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
			"token_type":    "bearer",
			"scope":         "openid email",
		})
	}))
	defer srv.Close()
	defer withIMS(t, srv)()

	dir := t.TempDir()
	s := &TokenStore{
		Path:         filepath.Join(dir, "tokens.json"),
		ClientID:     "cid",
		ClientSecret: "csec",
		RedirectURI:  "https://localhost:12345/callback",
	}
	if err := s.ExchangeCode(context.Background(), "the-code"); err != nil {
		t.Fatal(err)
	}

	if s.Access != "new-access" {
		t.Errorf("Access: %q", s.Access)
	}
	if s.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken: %q", s.RefreshToken)
	}
	if time.Until(s.ExpiresAt) < 50*time.Minute {
		t.Errorf("ExpiresAt should be ~1h away: %s", s.ExpiresAt)
	}

	if capturedForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type: %q", capturedForm.Get("grant_type"))
	}
	if capturedForm.Get("code") != "the-code" {
		t.Errorf("code: %q", capturedForm.Get("code"))
	}
	if capturedForm.Get("client_id") != "cid" {
		t.Errorf("client_id: %q", capturedForm.Get("client_id"))
	}

	// persisted to disk
	loaded, err := LoadTokenStore(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Access != "new-access" {
		t.Errorf("not persisted: Access=%q", loaded.Access)
	}
}

func TestTokenStore_Refresh(t *testing.T) {
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "rotated-access",
			"expires_in":   3600,
			"token_type":   "bearer",
		})
	}))
	defer srv.Close()
	defer withIMS(t, srv)()

	s := &TokenStore{
		Path:         filepath.Join(t.TempDir(), "t.json"),
		ClientID:     "cid",
		ClientSecret: "csec",
		Access:       "old-access",
		RefreshToken: "the-refresh-token",
		ExpiresAt:    time.Now().Add(-time.Minute), // expired
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Access != "rotated-access" {
		t.Errorf("Access: %q", s.Access)
	}
	// Refresh token retained when server didn't send a new one
	if s.RefreshToken != "the-refresh-token" {
		t.Errorf("RefreshToken should be retained: %q", s.RefreshToken)
	}
	if capturedForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type: %q", capturedForm.Get("grant_type"))
	}
	if capturedForm.Get("refresh_token") != "the-refresh-token" {
		t.Errorf("refresh_token: %q", capturedForm.Get("refresh_token"))
	}
}

func TestTokenStore_RefreshWithoutRefreshToken(t *testing.T) {
	s := &TokenStore{}
	err := s.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected error for empty refresh token")
	}
	if !strings.Contains(err.Error(), "refresh token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTokenStore_Valid_RefreshesNearExpiry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh",
			"expires_in":   3600,
			"token_type":   "bearer",
		})
	}))
	defer srv.Close()
	defer withIMS(t, srv)()

	s := &TokenStore{
		Path:         filepath.Join(t.TempDir(), "t.json"),
		ClientID:     "cid",
		ClientSecret: "csec",
		Access:       "stale",
		RefreshToken: "r",
		ExpiresAt:    time.Now().Add(10 * time.Second), // within skew
	}
	tok, err := s.Valid(context.Background(), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "fresh" {
		t.Errorf("expected refreshed token, got %q", tok)
	}
	if calls != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls)
	}

	// Second call within skew of the new expiry should NOT refresh again
	tok2, err := s.Valid(context.Background(), 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != "fresh" {
		t.Errorf("second call: got %q", tok2)
	}
	if calls != 1 {
		t.Errorf("second call triggered refresh, calls=%d", calls)
	}
}

func TestTokenStore_Valid_ErrorOnServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	defer withIMS(t, srv)()

	s := &TokenStore{
		Path:         filepath.Join(t.TempDir(), "t.json"),
		ClientID:     "cid",
		ClientSecret: "csec",
		RefreshToken: "r",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	if _, err := s.Valid(context.Background(), 60*time.Second); err == nil {
		t.Fatal("expected error on IMS 400")
	}
}
