package frameio

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Frame.io webhook signature + timestamp headers.
const (
	WebhookSignatureHeader = "X-Frameio-Signature"
	WebhookTimestampHeader = "X-Frameio-Request-Timestamp"
)

// WebhookVerify checks the HMAC-SHA256 signature on a Frame.io webhook
// request per Frame.io's documented scheme: sign v0:{timestamp}:{body} with
// the secret, expect the header as "v0=<hex>". Rejects timestamps older
// than maxAge (replay protection).
//
// Caller must pass the raw request body bytes (not a re-marshalled form).
func WebhookVerify(secret, signatureHeader, timestampHeader string, body []byte, maxAge time.Duration) error {
	if signatureHeader == "" || timestampHeader == "" {
		return errors.New("webhook: missing signature or timestamp headers")
	}
	tsSecs, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("webhook: bad timestamp: %w", err)
	}
	ts := time.Unix(tsSecs, 0)
	if maxAge > 0 {
		if delta := time.Since(ts); delta < -maxAge || delta > maxAge {
			return fmt.Errorf("webhook: timestamp out of range (delta=%s)", delta)
		}
	}
	msg := fmt.Sprintf("v0:%d:%s", tsSecs, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signatureHeader)) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// WebhookEvent is the shape of a Frame.io V4 webhook POST body. We parse
// a narrow subset of fields; the Resource payload's inner shape varies by
// event type, so we keep it as raw JSON for the consumer to interpret.
type WebhookEvent struct {
	Type     string          `json:"type"` // e.g. "file.upload.completed"
	ID       string          `json:"id"`   // webhook delivery ID
	User     json.RawMessage `json:"user"` // who caused the event
	Resource struct {
		Type string `json:"type"` // "file", "folder", etc.
		ID   string `json:"id"`
	} `json:"resource"`
	Data json.RawMessage `json:"data"`
}

// ReadWebhookBody reads the full request body (needed for signature
// verification before JSON-decoding).
func ReadWebhookBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MiB
	}
	return io.ReadAll(io.LimitReader(r.Body, maxBytes))
}

// RegisterWebhook creates a webhook scoped to a workspace, pointing at
// publicURL and subscribed to the given event types. Returns the signing
// secret Frame.io will use for future deliveries. V4 scopes webhooks
// per-workspace (not per-account).
func (c *Client) RegisterWebhook(ctx context.Context, workspaceID, publicURL string, events []string) (secret, id string, err error) {
	body, _ := json.Marshal(map[string]any{
		"data": map[string]any{
			"url":    publicURL,
			"events": events,
			"name":   "frameio-immich-relay",
		},
	})
	access, err := c.Tokens.Valid(ctx, 60*time.Second)
	if err != nil {
		return "", "", err
	}
	path := c.accountPath("/workspaces/" + workspaceID + "/webhooks")
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+path, newBytesReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return "", "", fmt.Errorf("frameio: register webhook: %s: %s", resp.Status, string(rb))
	}
	var wrap struct {
		Data struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return "", "", fmt.Errorf("frameio: decode webhook response: %w", err)
	}
	return wrap.Data.Secret, wrap.Data.ID, nil
}

// DeleteWebhook removes a previously-created webhook. V4 quirk: create
// is scoped to a workspace, but delete is scoped only to the account
// (webhook_id alone identifies it).
func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	_, err := c.do(ctx, "DELETE", c.accountPath("/webhooks/"+id), nil, nil)
	return err
}
