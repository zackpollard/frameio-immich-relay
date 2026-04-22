// Package immich talks to a self-hosted Immich server for asset ingestion.
// Scoped to exactly what the Frame.io relay needs: dedup-check + upload.
// No album handling, no user metadata, no read-side endpoints beyond the
// dedup check. API auth is a static x-api-key header.
package immich

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultDeviceID = "frameio-relay"

// Client is a minimal Immich v1 API client.
type Client struct {
	BaseURL  string // e.g. "https://immich.zackpollard.pro" — no trailing slash
	APIKey   string
	DeviceID string // identifies this relay to Immich; default "frameio-relay"
	HTTP     *http.Client
}

// NewClient builds a Client with sensible defaults.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		APIKey:   apiKey,
		DeviceID: defaultDeviceID,
		HTTP:     &http.Client{Timeout: 10 * time.Minute},
	}
}

// CheckResult is Immich's verdict for a single file in a bulk-upload-check.
type CheckResult struct {
	Action  string // "accept" (new, safe to upload) or "reject"
	Reason  string // "duplicate" when reject
	AssetID string // existing Immich asset ID when duplicate
}

// BulkCheck asks Immich whether each (id, sha1-hex) pair is already present.
// Pass a small map per call — Immich enforces rate limits but accepts hundreds
// of entries per request. Returns one result per input id.
func (c *Client) BulkCheck(ctx context.Context, checksums map[string]string) (map[string]CheckResult, error) {
	type asset struct {
		ID       string `json:"id"`
		Checksum string `json:"checksum"`
	}
	assets := make([]asset, 0, len(checksums))
	for id, sum := range checksums {
		assets = append(assets, asset{ID: id, Checksum: sum})
	}
	body, err := json.Marshal(map[string]any{"assets": assets})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/assets/bulk-upload-check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("immich bulk-check %s: %s", resp.Status, string(b))
	}

	var parsed struct {
		Results []struct {
			ID      string `json:"id"`
			Action  string `json:"action"`
			Reason  string `json:"reason,omitempty"`
			AssetID string `json:"assetId,omitempty"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("immich bulk-check decode: %w", err)
	}
	out := make(map[string]CheckResult, len(parsed.Results))
	for _, r := range parsed.Results {
		out[r.ID] = CheckResult{Action: r.Action, Reason: r.Reason, AssetID: r.AssetID}
	}
	return out, nil
}

// Upload sends a file to Immich. Timestamps should be the file's
// created-at / modified-at. Returns the Immich asset ID.
func (c *Client) Upload(ctx context.Context, path, deviceAssetID string, createdAt, modifiedAt time.Time) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Photo-sized files fit in RAM comfortably. If this ever has to handle
	// very large video, swap to io.Pipe + goroutine streaming.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("deviceAssetId", deviceAssetID); err != nil {
		return "", err
	}
	if err := mw.WriteField("deviceId", c.DeviceID); err != nil {
		return "", err
	}
	if err := mw.WriteField("fileCreatedAt", createdAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if err := mw.WriteField("fileModifiedAt", modifiedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	fw, err := mw.CreateFormFile("assetData", filepath.Base(path))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/assets", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", fmt.Errorf("immich upload %s: %s", resp.Status, string(b))
	}

	var parsed struct {
		ID     string `json:"id"`
		Status string `json:"status"` // "created" or "duplicate"
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("immich upload decode: %w", err)
	}
	if parsed.ID == "" {
		return "", fmt.Errorf("immich upload: no id in response")
	}
	return parsed.ID, nil
}

// EnsureUploaded uploads the file iff Immich doesn't already have a byte-
// identical copy. Returns the (existing or new) Immich asset ID and whether
// an upload actually happened.
func (c *Client) EnsureUploaded(ctx context.Context, path, deviceAssetID string, createdAt, modifiedAt time.Time) (assetID string, uploaded bool, err error) {
	sum, err := FileSHA1(path)
	if err != nil {
		return "", false, fmt.Errorf("sha1: %w", err)
	}
	checks, err := c.BulkCheck(ctx, map[string]string{deviceAssetID: sum})
	if err != nil {
		return "", false, err
	}
	res := checks[deviceAssetID]
	if res.Action == "reject" && res.Reason == "duplicate" && res.AssetID != "" {
		return res.AssetID, false, nil
	}
	id, err := c.Upload(ctx, path, deviceAssetID, createdAt, modifiedAt)
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}

// FileSHA1 returns the hex-encoded SHA-1 of the file's bytes. Immich's
// dedup system specifically uses SHA-1.
func FileSHA1(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
