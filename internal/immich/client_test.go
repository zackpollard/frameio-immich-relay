package immich

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSHA1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	payload := []byte("hello world")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := FileSHA1(path)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha1.Sum(payload)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestFileSHA1_MissingFile(t *testing.T) {
	if _, err := FileSHA1(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestClient_BulkCheck_Accept(t *testing.T) {
	var captured struct {
		Assets []struct {
			ID       string `json:"id"`
			Checksum string `json:"checksum"`
		} `json:"assets"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/assets/bulk-upload-check" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "the-key" {
			t.Errorf("x-api-key: %s", r.Header.Get("x-api-key"))
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type: %s", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&captured)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"id": "file-1", "action": "accept"},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "the-key")
	out, err := c.BulkCheck(context.Background(), map[string]string{"file-1": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if out["file-1"].Action != "accept" {
		t.Errorf("action: %s", out["file-1"].Action)
	}
	if len(captured.Assets) != 1 || captured.Assets[0].ID != "file-1" || captured.Assets[0].Checksum != "abc123" {
		t.Errorf("captured request: %+v", captured)
	}
}

func TestClient_BulkCheck_Reject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"id": "file-1", "action": "reject", "reason": "duplicate", "assetId": "existing-asset"},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	out, err := c.BulkCheck(context.Background(), map[string]string{"file-1": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	r := out["file-1"]
	if r.Action != "reject" || r.Reason != "duplicate" || r.AssetID != "existing-asset" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestClient_BulkCheck_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"boom"}`, 500)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k")
	if _, err := c.BulkCheck(context.Background(), map[string]string{"x": "y"}); err == nil {
		t.Fatal("expected 500 error")
	}
}

func TestClient_Upload(t *testing.T) {
	type fields struct {
		deviceAssetID  string
		deviceID       string
		fileCreatedAt  string
		fileModifiedAt string
		filename       string
		body           []byte
	}
	var got fields

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/assets" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("method: %s", r.Method)
		}
		if r.Header.Get("x-api-key") != "the-key" {
			t.Errorf("x-api-key missing")
		}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(part)
			switch part.FormName() {
			case "deviceAssetId":
				got.deviceAssetID = string(data)
			case "deviceId":
				got.deviceID = string(data)
			case "fileCreatedAt":
				got.fileCreatedAt = string(data)
			case "fileModifiedAt":
				got.fileModifiedAt = string(data)
			case "assetData":
				got.filename = part.FileName()
				got.body = data
			}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "immich-asset-1",
			"status": "created",
		})
	}))
	defer srv.Close()

	payload := []byte{1, 2, 3, 4, 5}
	path := filepath.Join(t.TempDir(), "DSCF1234.JPG")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewClient(srv.URL, "the-key")
	created := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	modified := time.Date(2026, 4, 22, 11, 0, 0, 0, time.UTC)
	id, err := c.Upload(context.Background(), path, "frameio-uuid-1", created, modified)
	if err != nil {
		t.Fatal(err)
	}
	if id != "immich-asset-1" {
		t.Errorf("id: %s", id)
	}
	if got.deviceAssetID != "frameio-uuid-1" {
		t.Errorf("deviceAssetId: %q", got.deviceAssetID)
	}
	if got.deviceID != defaultDeviceID {
		t.Errorf("deviceId: %q", got.deviceID)
	}
	if !strings.Contains(got.fileCreatedAt, "2026-04-22T10:00:00") {
		t.Errorf("fileCreatedAt: %q", got.fileCreatedAt)
	}
	if got.filename != "DSCF1234.JPG" {
		t.Errorf("filename: %q", got.filename)
	}
	if string(got.body) != string(payload) {
		t.Errorf("body bytes differ")
	}
}

func TestClient_EnsureUploaded_NewFile(t *testing.T) {
	var uploaded bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/assets/bulk-upload-check":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{{"id": "asset-key", "action": "accept"}},
			})
		case "/api/assets":
			uploaded = true
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "new-asset", "status": "created"})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.URL, "k")
	id, wasNew, err := c.EnsureUploaded(context.Background(), path, "asset-key", time.Now(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !wasNew {
		t.Error("expected upload path to run")
	}
	if id != "new-asset" {
		t.Errorf("id: %s", id)
	}
	if !uploaded {
		t.Error("/api/assets was never hit")
	}
}

func TestClient_EnsureUploaded_Duplicate(t *testing.T) {
	var uploadCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/assets/bulk-upload-check":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{"id": "asset-key", "action": "reject", "reason": "duplicate", "assetId": "existing"},
				},
			})
		case "/api/assets":
			uploadCalled = true
			w.WriteHeader(201)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.URL, "k")
	id, wasNew, err := c.EnsureUploaded(context.Background(), path, "asset-key", time.Now(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if wasNew {
		t.Error("duplicate should not upload")
	}
	if id != "existing" {
		t.Errorf("id: %s", id)
	}
	if uploadCalled {
		t.Error("upload endpoint hit on duplicate")
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	c := NewClient("https://immich.example.com/", "k")
	if !strings.HasSuffix(c.BaseURL, "com") {
		t.Errorf("trailing slash not trimmed: %s", c.BaseURL)
	}
}

// silence unused variable warnings if multipart types move around
var _ = multipart.NewReader
