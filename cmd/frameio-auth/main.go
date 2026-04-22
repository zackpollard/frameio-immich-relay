// frameio-auth performs the one-time interactive OAuth 2.0 authorization-code
// flow with Adobe IMS to obtain the initial access + refresh tokens for a
// Frame.io V4 account. After a successful login in the browser, it writes
// the tokens to a JSON file the relay reads.
//
// Run once per account. Re-run if the refresh token is ever invalidated.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
)

func main() {
	tokensPath := flag.String("tokens", "tokens.json", "file to write the access + refresh tokens to")
	clientID := flag.String("client-id", os.Getenv("FRAMEIO_CLIENT_ID"), "OAuth client ID from Adobe Developer Console")
	clientSecret := flag.String("client-secret", os.Getenv("FRAMEIO_CLIENT_SECRET"), "OAuth client secret from Adobe Developer Console")
	port := flag.Int("port", 12345, "local port for the OAuth redirect listener")
	scopes := flag.String("scopes", "openid email profile offline_access additional_info.roles", "space-separated OAuth scopes to request")
	flag.Parse()

	if *clientID == "" || *clientSecret == "" {
		log.Fatal("-client-id and -client-secret (or FRAMEIO_CLIENT_ID / FRAMEIO_CLIENT_SECRET) required")
	}

	// Adobe Developer Console requires HTTPS for redirect URIs even on
	// loopback and rejects raw IPs, so we use "localhost" and serve TLS
	// with a self-signed cert for it. Browser will warn on first visit;
	// accept the risk to proceed (cert is regenerated every run).
	redirectURI := fmt.Sprintf("https://localhost:%d/callback", *port)

	store, err := frameio.LoadTokenStore(*tokensPath)
	if err != nil {
		log.Fatalf("load %s: %v", *tokensPath, err)
	}
	store.ClientID = *clientID
	store.ClientSecret = *clientSecret
	store.RedirectURI = redirectURI
	if err := store.Save(); err != nil {
		log.Fatalf("save initial store: %v", err)
	}

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	authURL := store.AuthorizeURL(state, strings.Fields(*scopes))

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("Open the following URL in your browser and grant access:")
	fmt.Println()
	fmt.Println("  " + authURL)
	fmt.Println()
	fmt.Printf("After login, the browser will redirect to %s.\n", redirectURI)
	fmt.Println("The redirect uses a self-signed cert — accept the browser warning once.")
	fmt.Println("This process will exit automatically once tokens are saved.")
	fmt.Println("--------------------------------------------------------------------------------")

	done := make(chan struct{})
	var flowErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			flowErr = fmt.Errorf("oauth error: %s: %s", e, q.Get("error_description"))
			http.Error(w, flowErr.Error(), http.StatusBadRequest)
			close(done)
			return
		}
		if q.Get("state") != state {
			flowErr = fmt.Errorf("oauth: state mismatch (got %q)", q.Get("state"))
			http.Error(w, flowErr.Error(), http.StatusBadRequest)
			close(done)
			return
		}
		code := q.Get("code")
		if code == "" {
			flowErr = fmt.Errorf("oauth: no code in callback")
			http.Error(w, flowErr.Error(), http.StatusBadRequest)
			close(done)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := store.ExchangeCode(ctx, code); err != nil {
			flowErr = err
			http.Error(w, err.Error(), http.StatusInternalServerError)
			close(done)
			return
		}
		fmt.Fprintln(w, "OK — tokens saved. You can close this tab.")
		close(done)
	})

	tlsCert, err := selfSignedLoopbackCert()
	if err != nil {
		log.Fatalf("self-signed cert: %v", err)
	}
	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", *port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-done
	_ = srv.Close()

	if flowErr != nil {
		log.Fatalf("auth failed: %v", flowErr)
	}
	log.Printf("tokens written to %s (access token expires at %s UTC)", *tokensPath, store.ExpiresAt.UTC().Format(time.RFC3339))
}

// selfSignedLoopbackCert mints an ephemeral RSA cert valid for 127.0.0.1,
// signed by itself. Good enough for Adobe's HTTPS redirect requirement —
// the browser will warn but let the user proceed, and the cert is thrown
// away after this process exits.
func selfSignedLoopbackCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "frameio-auth localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
