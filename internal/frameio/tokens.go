package frameio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Adobe IMS endpoints used by the Frame.io V4 OAuth flow.
const (
	IMSAuthorizeURL = "https://ims-na1.adobelogin.com/ims/authorize/v2"
	IMSTokenURL     = "https://ims-na1.adobelogin.com/ims/token/v3"
)

// TokenStore persists OAuth credentials + access/refresh tokens on disk and
// auto-refreshes the access token when it's close to expiry.
type TokenStore struct {
	Path string `json:"-"`

	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RedirectURI  string    `json:"redirect_uri"`
	Access       string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope"`

	mu sync.Mutex
}

// LoadTokenStore reads the tokens file from disk. Returns an empty store
// (with Path set) if the file doesn't exist, so callers can populate it.
func LoadTokenStore(path string) (*TokenStore, error) {
	s := &TokenStore{Path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	s.Path = path
	return s, nil
}

// Save atomically persists the store to its configured path with 0600 perms
// (tokens are secrets).
func (s *TokenStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *TokenStore) saveLocked() error {
	if s.Path == "" {
		return errors.New("tokens: no path set")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// AuthorizeURL constructs the IMS authorization URL for the one-time
// browser login that yields an authorization code.
func (s *TokenStore) AuthorizeURL(state string, scopes []string) string {
	q := url.Values{}
	q.Set("client_id", s.ClientID)
	q.Set("redirect_uri", s.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	if state != "" {
		q.Set("state", state)
	}
	return IMSAuthorizeURL + "?" + q.Encode()
}

// ExchangeCode swaps an authorization code for access + refresh tokens and
// persists them. Call this from the local OAuth callback handler.
func (s *TokenStore) ExchangeCode(ctx context.Context, code string) error {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", s.ClientID)
	form.Set("client_secret", s.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", s.RedirectURI)
	return s.tokenRequest(ctx, form)
}

// Refresh uses the current refresh token to mint a new access token.
// Called automatically by Valid() when needed, but exposed for tests.
func (s *TokenStore) Refresh(ctx context.Context) error {
	s.mu.Lock()
	refresh := s.RefreshToken
	clientID := s.ClientID
	clientSecret := s.ClientSecret
	s.mu.Unlock()

	if refresh == "" {
		return errors.New("tokens: no refresh token stored; run frameio-auth first")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refresh)
	return s.tokenRequest(ctx, form)
}

// Valid ensures Access is non-empty and not within `skew` of expiring,
// refreshing if needed. Returns the current access token.
func (s *TokenStore) Valid(ctx context.Context, skew time.Duration) (string, error) {
	s.mu.Lock()
	access := s.Access
	exp := s.ExpiresAt
	s.mu.Unlock()

	if access == "" || time.Until(exp) < skew {
		if err := s.Refresh(ctx); err != nil {
			return "", err
		}
		s.mu.Lock()
		access = s.Access
		s.mu.Unlock()
	}
	return access, nil
}

func (s *TokenStore) tokenRequest(ctx context.Context, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, "POST", IMSTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("ims token: %s: %s", resp.Status, string(body))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("ims decode: %w", err)
	}
	if tr.AccessToken == "" {
		return errors.New("ims: empty access_token in response")
	}

	s.mu.Lock()
	s.Access = tr.AccessToken
	if tr.RefreshToken != "" { // refresh flow sometimes omits it
		s.RefreshToken = tr.RefreshToken
	}
	s.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.Scope != "" {
		s.Scope = tr.Scope
	}
	err = s.saveLocked()
	s.mu.Unlock()
	return err
}
