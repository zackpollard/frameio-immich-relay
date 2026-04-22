package frameio

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClient creates a frameio.Client pointed at httptest.Server url,
// with a hand-crafted TokenStore that never needs to hit IMS (ExpiresAt
// far in the future).
func newTestClient(t *testing.T, accountID, srvURL string) *Client {
	t.Helper()
	return &Client{
		Tokens: &TokenStore{
			Path:         filepath.Join(t.TempDir(), "t.json"),
			Access:       "test-access",
			RefreshToken: "r",
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		},
		AccountID: accountID,
		Base:      srvURL + "/v4",
		HTTP:      &http.Client{Timeout: 5 * time.Second},
	}
}

func TestClient_Me(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/me" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-access" {
			t.Errorf("Authorization: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"id": "u-1", "name": "Zack", "email": "z@example.com"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "", srv.URL)
	name, err := c.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if name != "Zack" {
		t.Errorf("got %q", name)
	}
}

func TestClient_Me_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, "", srv.URL)
	if _, err := c.Me(context.Background()); err == nil {
		t.Fatal("expected 401 error")
	}
}

func TestClient_ListAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/accounts" {
			t.Errorf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "acct-1", "display_name": "One"},
				{"id": "acct-2", "display_name": "Two"},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "", srv.URL)
	accts, err := c.ListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 2 || accts[0].ID != "acct-1" || accts[1].DisplayName != "Two" {
		t.Errorf("unexpected: %+v", accts)
	}
}

func TestClient_ListWorkspaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v4/accounts/a1/workspaces"
		if r.URL.Path != want {
			t.Errorf("path: got %s want %s", r.URL.Path, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "w1", "name": "Main"}},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	ws, err := c.ListWorkspaces(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || ws[0].Name != "Main" {
		t.Errorf("unexpected: %+v", ws)
	}
}

func TestClient_ListProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v4/accounts/a1/workspaces/w1/projects"
		if r.URL.Path != want {
			t.Errorf("path: got %s want %s", r.URL.Path, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "p1", "name": "Cam", "root_folder_id": "rf1"}},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	ps, err := c.ListProjects(context.Background(), "a1", "w1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].RootFolderID != "rf1" {
		t.Errorf("unexpected: %+v", ps)
	}
}

func TestClient_ListFolderChildren_Pagination(t *testing.T) {
	// Return two pages; first carries next_cursor, second doesn't.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		if r.URL.Query().Get("page_size") != "100" {
			t.Errorf("page_size: %q", r.URL.Query().Get("page_size"))
		}
		if after == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "f1", "type": "file", "name": "a.jpg"}},
				"meta": map[string]any{"next_cursor": "page2"},
			})
			return
		}
		if after != "page2" {
			t.Errorf("unexpected cursor: %q", after)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "f2", "type": "file", "name": "b.jpg"}},
			"meta": map[string]any{"next_cursor": ""},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	files, err := c.ListFolderChildren(context.Background(), "root-folder")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].ID != "f1" || files[1].ID != "f2" {
		t.Errorf("pagination: %+v", files)
	}
}

func TestClient_GetFile_IncludesMediaLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("include"); got != "media_links.original" {
			t.Errorf("include: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":     "file-1",
				"name":   "DSCF0001.JPG",
				"status": "uploaded",
				"type":   "file",
				"media_links": map[string]any{
					"original": map[string]any{
						"download_url": "https://s3.example.com/bucket/file-1",
					},
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	f, err := c.GetFile(context.Background(), "file-1")
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsReady() {
		t.Error("file should be ready")
	}
	if f.MediaLinks.Original == nil || f.MediaLinks.Original.DownloadURL == "" {
		t.Error("media_links.original.download_url not populated")
	}
}

func TestClient_Download(t *testing.T) {
	payload := []byte("binary contents")
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "15")
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	}))
	defer s3.Close()

	c := newTestClient(t, "a1", "http://unused")
	f := File{
		ID: "f1",
		MediaLinks: MediaLinks{
			Original: &MediaLink{DownloadURL: s3.URL + "/obj"},
		},
	}
	rc, size, err := c.Download(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if size != 15 {
		t.Errorf("size: %d", size)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "binary contents" {
		t.Errorf("body: %q", got)
	}
}

func TestClient_Download_NoURL(t *testing.T) {
	c := newTestClient(t, "a1", "http://unused")
	_, _, err := c.Download(context.Background(), File{ID: "x"})
	if err == nil {
		t.Fatal("expected error on missing download url")
	}
}

func TestClient_DeleteFile(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != "DELETE" {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.Path != "/v4/accounts/a1/files/file-1" {
			t.Errorf("path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	if err := c.DeleteFile(context.Background(), "file-1"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("handler not called")
	}
}

func TestClient_RegisterWebhook(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.Path != "/v4/accounts/a1/workspaces/w1/webhooks" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type: %s", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"id": "wh-1", "secret": "sek"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	secret, id, err := c.RegisterWebhook(context.Background(), "w1", "https://example/webhook", []string{"file.upload.completed"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "wh-1" || secret != "sek" {
		t.Errorf("id=%s secret=%s", id, secret)
	}
	data := captured["data"].(map[string]any)
	if data["url"] != "https://example/webhook" {
		t.Errorf("payload url: %v", data["url"])
	}
	events := data["events"].([]any)
	if len(events) != 1 || events[0] != "file.upload.completed" {
		t.Errorf("payload events: %v", events)
	}
}

func TestClient_DeleteWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.Path != "/v4/accounts/a1/webhooks/wh-1" {
			t.Errorf("path: %s", r.URL.Path)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	if err := c.DeleteWebhook(context.Background(), "wh-1"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_do_SendsAuthAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept: %s", r.Header.Get("Accept"))
		}
		if r.Header.Get("x-api-version") != "v4" {
			t.Errorf("x-api-version: %s", r.Header.Get("x-api-version"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "x"}})
	}))
	defer srv.Close()

	c := newTestClient(t, "a1", srv.URL)
	if _, err := c.Me(context.Background()); err != nil {
		t.Fatal(err)
	}
}
