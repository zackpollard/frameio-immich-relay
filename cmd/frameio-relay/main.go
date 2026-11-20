// frameio-relay consumes Frame.io V4 webhook deliveries, downloads each
// completed C2C upload to local storage, and deletes the file from
// Frame.io. A background polling loop runs as a reconcile fallback in case
// webhooks are dropped / missed.
//
// Requires: tokens.json (from frameio-auth), an account_id, a folder_id
// to scope downloads to, and a publicly-reachable HTTPS URL for webhook
// delivery (Cloudflare Tunnel is the easiest way to get this).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/admin"
	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
	"github.com/zackpollard/frameio-immich-relay/internal/immich"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	tokensPath := flag.String("tokens", "tokens.json", "path to tokens.json written by frameio-auth")
	accountID := flag.String("account", os.Getenv("FRAMEIO_ACCOUNT"), "Frame.io V4 account_id")
	workspaceID := flag.String("workspace", os.Getenv("FRAMEIO_WORKSPACE"), "Frame.io V4 workspace_id (required if -public-url is set; webhooks are workspace-scoped)")
	folderID := flag.String("folder", os.Getenv("FRAMEIO_FOLDER"), "root folder ID to watch for C2C uploads (recurses into subfolders)")
	webhookAddr := flag.String("webhook-addr", ":9000", "local listen address for webhook deliveries")
	publicURL := flag.String("public-url", os.Getenv("FRAMEIO_PUBLIC_URL"), "publicly-reachable HTTPS URL that routes to -webhook-addr (e.g. https://xxx.trycloudflare.com)")
	outDir := flag.String("out", "downloads", "local directory for downloaded files")
	stateFile := flag.String("state", "relay-state.json", "local state file tracking processed file IDs + webhook secret")
	pollInterval := flag.Duration("poll", 60*time.Second, "reconcile polling interval (backup for missed webhooks)")
	stuckTimeout := flag.Duration("stuck-timeout", envDuration("FRAMEIO_STUCK_TIMEOUT", 0), "delete non-ready Frame.io files older than this (0 = never). Frame.io does not auto-clean abandoned uploads; a stuck file eats your quota forever.")
	dryRun := flag.Bool("dry-run", false, "download but do not delete from Frame.io or Immich-upload")
	immichURL := flag.String("immich-url", os.Getenv("IMMICH_URL"), "Immich base URL, e.g. https://immich.example.com; empty disables Immich integration")
	immichKey := flag.String("immich-key", os.Getenv("IMMICH_API_KEY"), "Immich API key (x-api-key header)")
	adminPassword := flag.String("admin-password", os.Getenv("ADMIN_PASSWORD"), "admin panel login password; empty disables the panel at /admin on the webhook port")
	adminSessionTTL := flag.Duration("admin-session-ttl", envDuration("ADMIN_SESSION_TTL", 12*time.Hour), "admin panel session lifetime")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	tokens, err := frameio.LoadTokenStore(*tokensPath)
	if err != nil {
		log.Fatalf("load tokens: %v", err)
	}
	if tokens.ClientID == "" || tokens.RefreshToken == "" {
		log.Fatalf("tokens file %s is incomplete — run frameio-auth first", *tokensPath)
	}
	client := frameio.NewClient(tokens, *accountID)

	st, err := loadState(*stateFile)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	name, err := client.Me(ctx)
	if err != nil {
		log.Fatalf("auth check: %v", err)
	}
	log.Printf("authenticated as %s", name)

	if err := autoDiscover(ctx, client, accountID, workspaceID, folderID); err != nil {
		log.Fatalf("auto-discover: %v", err)
	}
	if *accountID == "" {
		log.Fatal("FRAMEIO_ACCOUNT required (discovery did not find one)")
	}
	if *folderID == "" {
		log.Fatal("FRAMEIO_FOLDER required (discovery did not find one)")
	}
	client.AccountID = *accountID

	var imm *immich.Client
	if *immichURL != "" {
		if *immichKey == "" {
			log.Fatalf("-immich-url set but -immich-key empty")
		}
		imm = immich.NewClient(*immichURL, *immichKey)
		log.Printf("Immich integration enabled: %s", imm.BaseURL)
	} else {
		log.Printf("Immich integration disabled (set IMMICH_URL/IMMICH_API_KEY to enable)")
	}

	r := &relay{
		client:       client,
		tokens:       tokens,
		immich:       imm,
		folderID:     *folderID,
		outDir:       *outDir,
		stateFile:    *stateFile,
		state:        st,
		dryRun:       *dryRun,
		stuckTimeout: *stuckTimeout,
		publicURL:    *publicURL,
		pollInterval: *pollInterval,
		account:      *accountID,
		workspace:    *workspaceID,
		immichURL:    *immichURL,
		authName:     name,
		startedAt:    time.Now(),
		inflight:     map[string]struct{}{},
		whSecret:     st.WebhookSecret,
		events:       newEventLog(200),
	}
	r.eventf("authenticated as %s", name)

	// Register webhook if we have a public URL and don't already have one.
	if *publicURL != "" {
		if *workspaceID == "" {
			log.Fatalf("-workspace is required when -public-url is set (webhooks are workspace-scoped)")
		}
		if st.WebhookID == "" {
			secret, id, err := client.RegisterWebhook(ctx, *workspaceID, *publicURL, []string{"file.upload.completed"})
			if err != nil {
				log.Fatalf("register webhook: %v", err)
			}
			st.WebhookID = id
			st.WebhookSecret = secret
			st.WebhookWorkspace = *workspaceID
			if err := saveState(*stateFile, st); err != nil {
				log.Fatalf("save state after webhook register: %v", err)
			}
			r.eventf("registered webhook %s → %s", id, *publicURL)
		} else {
			r.eventf("reusing existing webhook %s (secret cached in state)", st.WebhookID)
		}
	} else {
		r.eventf("no -public-url set — running in polling-only mode")
	}

	// HTTP server on the webhook port: /webhook for Frame.io deliveries,
	// /admin for the optional login-protected admin panel (same tunnel).
	var adm *admin.Server
	if *adminPassword != "" {
		origin := publicOrigin(*publicURL)
		a, err := admin.New(admin.Config{
			Password:     *adminPassword,
			SessionTTL:   *adminSessionTTL,
			PublicOrigin: origin,
			Version:      version,
		}, &relayBackend{r: r, st: st})
		if err != nil {
			log.Fatalf("admin panel: %v", err)
		}
		adm = a
		if origin != "" {
			r.eventf("admin panel enabled at %s/admin (login required)", origin)
		} else {
			r.eventf("admin panel enabled on %s (login required; browser re-auth needs FRAMEIO_PUBLIC_URL)", *webhookAddr)
		}
	}
	go r.runHTTPServer(ctx, *webhookAddr, adm)

	// Startup sweep of any local files (orphans from a crashed Immich
	// upload, or from before Immich was enabled). No-op when Immich is
	// disabled. Must run before the poll loop so uploads don't race with
	// Frame.io-initiated processing of the same file.
	if err := r.reconcileLocal(ctx); err != nil {
		log.Printf("local reconcile: %v", err)
	}

	// Reconcile polling loop — catches anything missed by the webhook path.
	r.runPollLoop(ctx, *pollInterval)

	log.Printf("shutting down")
}

// autoDiscover fills in any of the account / workspace / folder IDs that
// the user did not provide, so long as there is exactly one reasonable
// choice at each level. Ambiguity (multiple accounts / workspaces /
// projects) is a hard error with instructions to set the relevant var.
func autoDiscover(ctx context.Context, client *frameio.Client, account, workspace, folder *string) error {
	if *account == "" {
		accounts, err := client.ListAccounts(ctx)
		if err != nil {
			return fmt.Errorf("list accounts: %w", err)
		}
		switch len(accounts) {
		case 0:
			return errors.New("no Frame.io accounts on this user; check your auth")
		case 1:
			*account = accounts[0].ID
			log.Printf("discovered account: %q (%s)", accounts[0].DisplayName, *account)
		default:
			return fmt.Errorf("%d accounts present; set FRAMEIO_ACCOUNT explicitly (run `frameio-auth -discover` to list)", len(accounts))
		}
	}
	if *workspace == "" {
		workspaces, err := client.ListWorkspaces(ctx, *account)
		if err != nil {
			return fmt.Errorf("list workspaces: %w", err)
		}
		switch len(workspaces) {
		case 0:
			return fmt.Errorf("no workspaces in account %s", *account)
		case 1:
			*workspace = workspaces[0].ID
			log.Printf("discovered workspace: %q (%s)", workspaces[0].Name, *workspace)
		default:
			return fmt.Errorf("%d workspaces in account; set FRAMEIO_WORKSPACE explicitly", len(workspaces))
		}
	}
	if *folder == "" {
		projects, err := client.ListProjects(ctx, *account, *workspace)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		switch len(projects) {
		case 0:
			return fmt.Errorf("no projects in workspace %s", *workspace)
		case 1:
			*folder = projects[0].RootFolderID
			log.Printf("discovered project: %q root_folder_id=%s", projects[0].Name, *folder)
		default:
			return fmt.Errorf("%d projects in workspace; set FRAMEIO_FOLDER explicitly to a project's root_folder_id", len(projects))
		}
	}
	return nil
}

// State --------------------------------------------------------------------

// state holds only webhook registration data. We deliberately do NOT persist
// a list of "already-seen" asset IDs: Frame.io itself is the source of truth.
// If an asset is still in the project, it's work to do — we detect
// already-completed downloads by checking local disk, and if the local copy
// exists with matching bytes we skip re-downloading and just retry delete.
type state struct {
	WebhookID        string `json:"webhook_id,omitempty"`
	WebhookSecret    string `json:"webhook_secret,omitempty"`
	WebhookWorkspace string `json:"webhook_workspace,omitempty"`
}

func loadState(path string) (*state, error) {
	s := &state{}
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
	return s, nil
}

func saveState(path string, s *state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Relay --------------------------------------------------------------------

type relay struct {
	client       *frameio.Client
	tokens       *frameio.TokenStore
	immich       *immich.Client // nil => skip Immich integration
	folderID     string
	outDir       string
	stateFile    string
	state        *state
	dryRun       bool
	stuckTimeout time.Duration // 0 = never clean up stuck uploads
	publicURL    string
	pollInterval time.Duration
	account      string
	workspace    string
	immichURL    string
	authName     string
	startedAt    time.Time

	mu       sync.Mutex
	inflight map[string]struct{} // asset IDs currently being processed

	stateMu sync.Mutex // guards state + its file writes (admin actions mutate it)

	whMu     sync.RWMutex
	whSecret string // live webhook signing secret (admin can re-register)

	events *eventLog // ring buffer shown on the admin dashboard
}

func (r *relay) runPollLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	if err := r.reconcile(ctx); err != nil {
		log.Printf("initial reconcile: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.reconcile(ctx); err != nil {
				log.Printf("reconcile: %v", err)
			}
		}
	}
}

// claim marks an asset as being processed. Returns false if someone else
// (webhook or an earlier reconcile iteration) is already handling it.
func (r *relay) claim(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.inflight[id]; busy {
		return false
	}
	r.inflight[id] = struct{}{}
	return true
}

func (r *relay) release(id string) {
	r.mu.Lock()
	delete(r.inflight, id)
	r.mu.Unlock()
}

// reconcileLocal walks outDir for any files present on disk and ensures
// Immich has them, deleting local copies on confirmed ingest. Intended
// for startup cleanup. No-op when Immich is disabled or dry-run is set.
func (r *relay) reconcileLocal(ctx context.Context) error {
	if r.immich == nil || r.dryRun {
		return nil
	}
	var paths []string
	err := filepath.WalkDir(r.outDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".part") {
			return nil // in-flight download
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	log.Printf("local reconcile: %d file(s) to backfill into Immich", len(paths))
	for _, p := range paths {
		if err := r.reconcileLocalFile(ctx, p); err != nil {
			log.Printf("local reconcile %s: %v", p, err)
		}
	}
	return nil
}

// reconcileLocalFile handles one orphan file: hash → bulk-check → upload
// if new → remove local copy. The dedup key uses a "local:" prefix so it
// can't collide with Frame.io file IDs in the inflight set.
func (r *relay) reconcileLocalFile(ctx context.Context, path string) error {
	deviceAssetID := "local:" + path
	if !r.claim(deviceAssetID) {
		return nil
	}
	defer r.release(deviceAssetID)

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mtime := info.ModTime()

	assetID, uploaded, err := r.immich.EnsureUploaded(ctx, path, filepath.Base(path), mtime, mtime)
	if err != nil {
		return err
	}
	if uploaded {
		log.Printf("local reconcile: %s → immich %s", path, assetID)
	} else {
		log.Printf("local reconcile: %s already in immich (%s)", path, assetID)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("local reconcile: remove %s: %v", path, err)
	}
	return nil
}

func (r *relay) reconcile(ctx context.Context) error {
	files, err := r.walk(ctx, r.folderID)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsReady() {
			if err := r.process(ctx, f); err != nil {
				r.eventf("[%s] reconcile process: %v", f.ID, err)
			}
			continue
		}
		if err := r.maybeReapStuck(ctx, f); err != nil {
			r.eventf("[%s] reap stuck: %v", f.ID, err)
		}
	}
	return nil
}

// maybeReapStuck deletes a non-ready file if it's been stuck longer than
// r.stuckTimeout. No-op when stuckTimeout is 0 or the file has no
// CreatedAt. Frame.io doesn't auto-clean abandoned uploads, so without
// this they'd accumulate in the user's storage quota forever.
func (r *relay) maybeReapStuck(ctx context.Context, f frameio.File) error {
	if r.stuckTimeout <= 0 || r.dryRun {
		return nil
	}
	if f.CreatedAt.IsZero() {
		return nil
	}
	age := time.Since(f.CreatedAt)
	if age < r.stuckTimeout {
		return nil
	}
	if !r.claim(f.ID) {
		return nil
	}
	defer r.release(f.ID)

	r.eventf("[%s] %s stuck in status=%q for %s (> %s); deleting", f.ID, f.Name, f.Status, age.Round(time.Second), r.stuckTimeout)
	return r.client.DeleteFile(ctx, f.ID)
}

func (r *relay) walk(ctx context.Context, rootID string) ([]frameio.File, error) {
	var out []frameio.File
	stack := []string{rootID}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		children, err := r.client.ListFolderChildren(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", id, err)
		}
		for _, c := range children {
			switch c.Type {
			case "folder", "version_stack":
				stack = append(stack, c.ID)
			case "file":
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// process downloads the file (if not already on disk) then deletes it from
// Frame.io. Idempotent: safe to call from both the webhook path and the
// reconcile poll; inflight dedup prevents simultaneous work on the same
// asset. Local-disk presence is the source of truth for "download done",
// so if the relay crashes between download and delete, the next call
// skips redownload and only retries the delete.
func (r *relay) process(ctx context.Context, f frameio.File) error {
	if !r.claim(f.ID) {
		return nil
	}
	defer r.release(f.ID)

	// If we got this from a webhook, media_links may be absent; refetch
	// with include=media_links.original to get the signed S3 URL.
	if f.MediaLinks.Original == nil || f.MediaLinks.Original.DownloadURL == "" {
		fresh, err := r.client.GetFile(ctx, f.ID)
		if err != nil {
			return fmt.Errorf("refetch: %w", err)
		}
		f = fresh
	}
	if !f.IsReady() {
		return fmt.Errorf("not ready (status=%s)", f.Status)
	}

	dst, tmp := r.localPath(f)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	// Skip re-download if a local file of the right size already exists.
	// Handles the crash-between-download-and-delete recovery case.
	skipDownload := false
	if info, err := os.Stat(dst); err == nil && info.Size() == f.FileSize && f.FileSize > 0 {
		r.eventf("[%s] %s — local copy exists (%d bytes); skipping download", f.ID, f.Name, f.FileSize)
		skipDownload = true
	}

	if !skipDownload {
		r.eventf("[%s] %s (%s, %d bytes) → %s", f.ID, f.Name, f.MediaType, f.FileSize, dst)
		body, _, err := r.client.Download(ctx, f)
		if err != nil {
			return fmt.Errorf("download: %w", err)
		}
		n, err := writeAndClose(tmp, body)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if f.FileSize > 0 && n != f.FileSize {
			_ = os.Remove(tmp)
			return fmt.Errorf("short write: got %d bytes, expected %d", n, f.FileSize)
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
	}

	if r.dryRun {
		r.eventf("[%s] dry-run: skipping Immich upload + Frame.io delete", f.ID)
		return nil
	}

	// Immich step (if configured). Must succeed before we touch Frame.io;
	// otherwise a failed ingest would leave us with no copy anywhere.
	if r.immich != nil {
		assetID, uploaded, err := r.immich.EnsureUploaded(ctx, dst, f.ID, f.CreatedAt, f.UpdatedAt)
		if err != nil {
			return fmt.Errorf("immich: %w", err)
		}
		if uploaded {
			r.eventf("[%s] immich uploaded: %s", f.ID, assetID)
		} else {
			r.eventf("[%s] immich already had it: %s", f.ID, assetID)
		}
		// Immich has it. Local copy is now redundant.
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			r.eventf("[%s] warning: remove local copy: %v", f.ID, err)
		}
	}

	if err := r.client.DeleteFile(ctx, f.ID); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	r.eventf("[%s] deleted from frame.io", f.ID)
	return nil
}

func (r *relay) localPath(f frameio.File) (dst, tmp string) {
	t := f.CreatedAt
	if t.IsZero() {
		t = time.Now().UTC()
	}
	name := f.Name
	if name == "" {
		name = f.ID
	}
	dst = filepath.Join(r.outDir, t.Format("2006"), t.Format("01-02"), name)
	return dst, dst + ".part"
}

// Webhook + admin HTTP server ----------------------------------------------
//
// One port serves both: /webhook for Frame.io deliveries (HMAC-verified,
// no session) and /admin for the login-protected panel, so a single tunnel
// in front of the port exposes both.

func (r *relay) runHTTPServer(ctx context.Context, addr string, adm *admin.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", r.handleWebhook)
	if adm != nil {
		mux.Handle("/", adm.Handler()) // inner mux owns the /admin... patterns
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if adm != nil {
		r.eventf("HTTP server listening on %s (webhook /webhook, admin /admin)", addr)
	} else {
		r.eventf("webhook server listening on %s (path /webhook)", addr)
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("http server: %v", err)
	}
}

func (r *relay) handleWebhook(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	secret := r.currentSecret()
	if secret == "" {
		http.Error(w, "webhook not registered", http.StatusServiceUnavailable)
		return
	}
	body, err := frameio.ReadWebhookBody(req, 1<<20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sig := req.Header.Get(frameio.WebhookSignatureHeader)
	ts := req.Header.Get(frameio.WebhookTimestampHeader)
	if err := frameio.WebhookVerify(secret, sig, ts, body, 5*time.Minute); err != nil {
		r.eventf("webhook: verify failed: %v", err)
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var evt frameio.WebhookEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.eventf("webhook: %s resource=%s/%s", evt.Type, evt.Resource.Type, evt.Resource.ID)

	// Respond immediately so Frame.io doesn't retry; handle the event async.
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")

	if evt.Type == "file.upload.completed" && evt.Resource.Type == "file" && evt.Resource.ID != "" {
		// process() handles dedup via inflight; no persistent check needed.
		go func(id string) {
			bg, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			f, err := r.client.GetFile(bg, id)
			if err != nil {
				r.eventf("webhook process: get %s: %v", id, err)
				return
			}
			if err := r.process(bg, f); err != nil {
				r.eventf("webhook process: %s: %v", id, err)
			}
		}(evt.Resource.ID)
	}
}

// Helpers ------------------------------------------------------------------

// envDuration parses an env var as a duration, returning fallback on empty
// or unparseable input. Used so stuck-timeout can also be set via the
// FRAMEIO_STUCK_TIMEOUT env var (friendlier for Docker Compose).
func envDuration(key string, fallback time.Duration) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

func writeAndClose(path string, body io.ReadCloser) (int64, error) {
	defer body.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

// Event log (admin dashboard ring buffer) -----------------------------------

type eventLog struct {
	mu  sync.Mutex
	buf []admin.Event
	max int
}

func newEventLog(max int) *eventLog { return &eventLog{max: max} }

func (e *eventLog) add(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.buf = append(e.buf, admin.Event{At: time.Now(), Msg: msg})
	if len(e.buf) > e.max {
		e.buf = e.buf[len(e.buf)-e.max:]
	}
}

// recent returns up to n newest events, newest first.
func (e *eventLog) recent(n int) []admin.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n > len(e.buf) {
		n = len(e.buf)
	}
	out := make([]admin.Event, n)
	copy(out, e.buf[len(e.buf)-n:])
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// eventf logs a line and records it for the admin dashboard.
func (r *relay) eventf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	r.events.add(msg)
}

// Admin backend ---------------------------------------------------------------

func (r *relay) inflightCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.inflight)
}

func (r *relay) setSecret(s string) {
	r.whMu.Lock()
	r.whSecret = s
	r.whMu.Unlock()
}

func (r *relay) currentSecret() string {
	r.whMu.RLock()
	defer r.whMu.RUnlock()
	return r.whSecret
}

// downloadStats counts files + bytes currently under the download dir.
func (r *relay) downloadStats() (files int, bytes int64) {
	_ = filepath.WalkDir(r.outDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			files++
			bytes += info.Size()
		}
		return nil
	})
	return files, bytes
}

// publicOrigin extracts scheme://host from the webhook public URL ("" if unset
// or unparseable). The admin panel lives at <origin>/admin and the browser
// OAuth callback at <origin>/admin/oauth/callback.
func publicOrigin(publicURL string) string {
	if publicURL == "" {
		return ""
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// relayBackend implements admin.Backend for the relay.
type relayBackend struct {
	r  *relay
	st *state
}

func (b *relayBackend) Status() admin.Status {
	r := b.r
	r.stateMu.Lock()
	whID := b.st.WebhookID
	r.stateMu.Unlock()
	origin := publicOrigin(r.publicURL)
	adminURL := ""
	if origin != "" {
		adminURL = origin + "/admin"
	}
	cID, cSecret := r.tokens.Credentials()
	credsOK := cID != "" && cSecret != ""
	return admin.Status{
		Version:        version,
		StartedAt:      r.startedAt,
		Uptime:         time.Since(r.startedAt).Round(time.Second).String(),
		Account:        r.account,
		Workspace:      r.workspace,
		Folder:         r.folderID,
		PublicURL:      r.publicURL,
		AdminURL:       adminURL,
		PollingOnly:    r.publicURL == "",
		ImmichURL:      r.immichURL,
		PollInterval:   r.pollInterval,
		StuckTimeout:   r.stuckTimeout,
		DryRun:         r.dryRun,
		Inflight:       r.inflightCount(),
		WebhookID:      whID,
		WebhookTarget:  r.publicURL,
		TokensPath:     r.tokens.Path,
		StateFile:      r.stateFile,
		OutDir:         r.outDir,
		AuthName:       r.authName,
		TokenExpiry:    r.tokens.Expiry(),
		HasRefresh:     r.tokens.HasRefreshToken(),
		AdminEnabled:   true,
		OAuthAvailable: origin != "" && credsOK,
	}
}

func (b *relayBackend) Events(n int) []admin.Event { return b.r.events.recent(n) }

func (b *relayBackend) AuthCheck(ctx context.Context) (string, error) {
	name, err := b.r.client.Me(ctx)
	if err != nil {
		return "", err
	}
	b.r.authName = name
	return name, nil
}

func (b *relayBackend) ReconcileNow() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := b.r.reconcile(ctx); err != nil {
			b.r.eventf("manual reconcile: %v", err)
		} else {
			b.r.eventf("manual reconcile: done")
		}
	}()
}

func (b *relayBackend) ReapStuckNow() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		files, err := b.r.walk(ctx, b.r.folderID)
		if err != nil {
			b.r.eventf("manual GC: walk: %v", err)
			return
		}
		n := 0
		for _, f := range files {
			if f.IsReady() {
				continue
			}
			if err := b.r.maybeReapStuck(ctx, f); err != nil {
				b.r.eventf("manual GC: [%s]: %v", f.ID, err)
			} else {
				n++
			}
		}
		b.r.eventf("manual GC: scanned %d non-ready file(s)", n)
	}()
}

func (b *relayBackend) RegisterWebhook(ctx context.Context) (string, error) {
	r := b.r
	if r.publicURL == "" {
		return "", errors.New("no FRAMEIO_PUBLIC_URL configured")
	}
	if r.workspace == "" {
		return "", errors.New("no FRAMEIO_WORKSPACE configured")
	}
	secret, id, err := r.client.RegisterWebhook(ctx, r.workspace, r.publicURL, []string{"file.upload.completed"})
	if err != nil {
		return "", err
	}
	r.stateMu.Lock()
	old := b.st.WebhookID
	b.st.WebhookID = id
	b.st.WebhookSecret = secret
	b.st.WebhookWorkspace = r.workspace
	saveErr := saveState(r.stateFile, b.st)
	r.stateMu.Unlock()
	if saveErr != nil {
		return "", saveErr
	}
	r.setSecret(secret)
	if old != "" && old != id {
		if derr := r.client.DeleteWebhook(ctx, old); derr != nil {
			r.eventf("old webhook %s delete failed (delete it manually): %v", old, derr)
		}
	}
	r.eventf("webhook registered %s → %s", id, r.publicURL)
	return id, nil
}

func (b *relayBackend) DeleteWebhook(ctx context.Context) error {
	r := b.r
	r.stateMu.Lock()
	id := b.st.WebhookID
	if id == "" {
		r.stateMu.Unlock()
		return nil
	}
	b.st.WebhookID = ""
	b.st.WebhookSecret = ""
	b.st.WebhookWorkspace = ""
	saveErr := saveState(r.stateFile, b.st)
	r.stateMu.Unlock()
	if saveErr != nil {
		return saveErr
	}
	r.setSecret("")
	if err := r.client.DeleteWebhook(ctx, id); err != nil {
		return err
	}
	r.eventf("webhook %s deleted; polling-only mode", id)
	return nil
}

func (b *relayBackend) ListWebhooks(ctx context.Context) ([]frameio.Webhook, error) {
	ws := b.r.workspace
	b.r.stateMu.Lock()
	if b.st.WebhookWorkspace != "" {
		ws = b.st.WebhookWorkspace
	}
	b.r.stateMu.Unlock()
	if ws == "" {
		return nil, errors.New("no workspace configured")
	}
	return b.r.client.ListWebhooks(ctx, ws)
}

func (b *relayBackend) ReloadTokens() error {
	return b.r.tokens.Reload()
}

func (b *relayBackend) ClientCredentials() (string, string, bool) {
	id, secret := b.r.tokens.Credentials()
	return id, secret, id != "" && secret != ""
}

// ExchangeOAuthCode runs the authorization-code exchange on a path-less
// throwaway TokenStore (so the public callback URL is never persisted as
// redirect_uri), then adopts the resulting tokens into the live store.
func (b *relayBackend) ExchangeOAuthCode(ctx context.Context, code, redirectURI string) error {
	r := b.r
	id, secret := r.tokens.Credentials()
	if id == "" || secret == "" {
		return errors.New("no Adobe client credentials in tokens.json")
	}
	tmp := &frameio.TokenStore{ClientID: id, ClientSecret: secret, RedirectURI: redirectURI}
	if err := tmp.ExchangeCode(ctx, code); err != nil {
		return err
	}
	if err := r.tokens.Adopt(tmp); err != nil {
		return err
	}
	r.eventf("browser OAuth exchange complete; tokens saved to %s", r.tokens.Path)
	return nil
}

func (b *relayBackend) DownloadStats() (int, int64) { return b.r.downloadStats() }

// StateView returns the relay state with the webhook secret masked out.
func (b *relayBackend) StateView() map[string]any {
	b.r.stateMu.Lock()
	defer b.r.stateMu.Unlock()
	return map[string]any{
		"webhook_id":         b.st.WebhookID,
		"webhook_workspace":  b.st.WebhookWorkspace,
		"webhook_secret_set": b.st.WebhookSecret != "",
		"state_file":         b.r.stateFile,
	}
}
