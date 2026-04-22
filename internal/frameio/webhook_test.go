package frameio

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// makeSig computes a Frame.io-style signature for given secret, timestamp,
// and body. Mirrors the verifier so test fixtures are guaranteed-valid.
func makeSig(secret string, ts time.Time, body []byte) (sigHeader, tsHeader string) {
	tsHeader = strconv.FormatInt(ts.Unix(), 10)
	msg := fmt.Sprintf("v0:%s:%s", tsHeader, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	sigHeader = "v0=" + hex.EncodeToString(mac.Sum(nil))
	return
}

func TestWebhookVerify_Valid(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{"type":"file.upload.completed","resource":{"type":"file","id":"abc"}}`)
	sig, ts := makeSig(secret, time.Now(), body)

	if err := WebhookVerify(secret, sig, ts, body, 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestWebhookVerify_WrongSecret(t *testing.T) {
	body := []byte(`{}`)
	sig, ts := makeSig("right-secret", time.Now(), body)

	err := WebhookVerify("wrong-secret", sig, ts, body, 5*time.Minute)
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected 'mismatch' in error, got: %v", err)
	}
}

func TestWebhookVerify_TamperedBody(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{"a":1}`)
	sig, ts := makeSig(secret, time.Now(), body)

	// body changed after signing
	tampered := []byte(`{"a":2}`)
	if err := WebhookVerify(secret, sig, ts, tampered, 5*time.Minute); err == nil {
		t.Fatal("tampered body should not verify")
	}
}

func TestWebhookVerify_MissingHeaders(t *testing.T) {
	cases := []struct{ sig, ts string }{
		{"", "1234567890"},
		{"v0=abc", ""},
		{"", ""},
	}
	for _, c := range cases {
		err := WebhookVerify("s", c.sig, c.ts, nil, time.Minute)
		if err == nil {
			t.Errorf("expected error for sig=%q ts=%q", c.sig, c.ts)
		}
	}
}

func TestWebhookVerify_BadTimestamp(t *testing.T) {
	err := WebhookVerify("s", "v0=abc", "not-a-number", nil, time.Minute)
	if err == nil {
		t.Fatal("expected bad timestamp error")
	}
}

func TestWebhookVerify_Expired(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{}`)
	// 10 minutes ago, with a 5-minute replay window.
	sig, ts := makeSig(secret, time.Now().Add(-10*time.Minute), body)

	err := WebhookVerify(secret, sig, ts, body, 5*time.Minute)
	if err == nil {
		t.Fatal("expected stale-timestamp error")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("want 'out of range' error, got: %v", err)
	}
}

func TestWebhookVerify_FutureTimestamp(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{}`)
	sig, ts := makeSig(secret, time.Now().Add(10*time.Minute), body)

	err := WebhookVerify(secret, sig, ts, body, 5*time.Minute)
	if err == nil {
		t.Fatal("expected out-of-range error for future timestamp")
	}
}

func TestWebhookVerify_NoReplayCheck(t *testing.T) {
	// maxAge <= 0 disables the replay window — useful for tests / dev mode.
	secret := "s"
	body := []byte(`{}`)
	sig, ts := makeSig(secret, time.Now().Add(-24*time.Hour), body)
	if err := WebhookVerify(secret, sig, ts, body, 0); err != nil {
		t.Fatalf("should accept old timestamp when maxAge=0: %v", err)
	}
}
