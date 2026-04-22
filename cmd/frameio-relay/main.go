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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zackpollard/frameio-immich-relay/internal/frameio"
	"github.com/zackpollard/frameio-immich-relay/internal/immich"
)

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
		immich:       imm,
		folderID:     *folderID,
		outDir:       *outDir,
		stateFile:    *stateFile,
		state:        st,
		dryRun:       *dryRun,
		stuckTimeout: *stuckTimeout,
		inflight:     map[string]struct{}{},
	}

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
			log.Printf("registered webhook %s → %s", id, *publicURL)
		} else {
			log.Printf("reusing existing webhook %s (secret cached in state)", st.WebhookID)
		}
	} else {
		log.Printf("no -public-url set — running in polling-only mode")
	}

	// HTTP server for webhook deliveries.
	if st.WebhookSecret != "" {
		go r.runWebhookServer(ctx, *webhookAddr, st.WebhookSecret)
	}

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
	immich       *immich.Client // nil => skip Immich integration
	folderID     string
	outDir       string
	stateFile    string
	state        *state
	dryRun       bool
	stuckTimeout time.Duration // 0 = never clean up stuck uploads

	mu       sync.Mutex
	inflight map[string]struct{} // asset IDs currently being processed
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
				log.Printf("[%s] reconcile process: %v", f.ID, err)
			}
			continue
		}
		if err := r.maybeReapStuck(ctx, f); err != nil {
			log.Printf("[%s] reap stuck: %v", f.ID, err)
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

	log.Printf("[%s] %s stuck in status=%q for %s (> %s); deleting", f.ID, f.Name, f.Status, age.Round(time.Second), r.stuckTimeout)
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
		log.Printf("[%s] %s — local copy exists (%d bytes); skipping download", f.ID, f.Name, f.FileSize)
		skipDownload = true
	}

	if !skipDownload {
		log.Printf("[%s] %s (%s, %d bytes) → %s", f.ID, f.Name, f.MediaType, f.FileSize, dst)
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
		log.Printf("[%s] dry-run: skipping Immich upload + Frame.io delete", f.ID)
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
			log.Printf("[%s] immich uploaded: %s", f.ID, assetID)
		} else {
			log.Printf("[%s] immich already had it: %s", f.ID, assetID)
		}
		// Immich has it. Local copy is now redundant.
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			log.Printf("[%s] warning: remove local copy: %v", f.ID, err)
		}
	}

	if err := r.client.DeleteFile(ctx, f.ID); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	log.Printf("[%s] deleted from frame.io", f.ID)
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

// Webhook server -----------------------------------------------------------

func (r *relay) runWebhookServer(ctx context.Context, addr, secret string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
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
			log.Printf("webhook: verify failed: %v", err)
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var evt frameio.WebhookEvent
		if err := json.Unmarshal(body, &evt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("webhook: %s resource=%s/%s", evt.Type, evt.Resource.Type, evt.Resource.ID)

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
					log.Printf("webhook process: get %s: %v", id, err)
					return
				}
				if err := r.process(bg, f); err != nil {
					log.Printf("webhook process: %s: %v", id, err)
				}
			}(evt.Resource.ID)
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("webhook server listening on %s (path /webhook)", addr)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("webhook server: %v", err)
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
