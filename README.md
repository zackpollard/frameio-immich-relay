# frameio-immich-relay

Self-hosted relay that pulls Frame.io Camera-to-Cloud uploads into an Immich library. Your camera uploads to Frame.io as normal; this service downloads each file over Frame.io's V4 API the moment it completes, ingests it into Immich with full EXIF, then deletes it from Frame.io so your free-tier quota stays clean.

Designed around the Fujifilm X-H2S (body-only, no FT-XH grip) and its native Frame.io C2C integration, but works with any camera / client that uploads to a Frame.io project.

```
Camera ──upload──▶ Frame.io cloud ──webhook──▶ this relay ──▶ Immich
                                                     │
                                                     └── delete from Frame.io
```

## Why this exists

Fujifilm's X-H2S natively uploads stills to Frame.io Camera-to-Cloud over Wi-Fi without the FT-XH file-transmitter grip. But Frame.io's camera-facing TLS is certificate-pinned, so you can't point the camera at a self-hosted server directly, and the body-only camera doesn't have FTP/FTPS options without the ~$900 grip accessory. The workaround: use Frame.io as a transit relay (free tier is fine with delete-after-download) and run this service to drain every upload into your own Immich instance as it lands.

## Features

- **Webhook-driven.** Registers a `file.upload.completed` webhook with Frame.io on first run; each upload triggers a sub-second download.
- **HMAC signature verification** on every webhook delivery (Frame.io's `v0:{ts}:{body}` scheme, SHA-256).
- **OAuth 2.0 via Adobe IMS** with automatic refresh-token rotation. Interactive one-time setup, then headless forever.
- **Immich dedup.** SHA-1 pre-check via `/api/assets/bulk-upload-check` means the relay never re-uploads a file Immich already has.
- **Idempotent crash recovery.** Local disk is the source of truth for "download finished". If the relay crashes between download and Immich upload, the next startup finds the local file and retries Immich without re-downloading. If it crashes between Immich upload and Frame.io delete, startup retries the delete.
- **Poll reconcile fallback.** In case a webhook is dropped, the relay walks the Frame.io folder every N seconds and picks up anything missed.
- **Startup local sweep.** Any stray files in the download directory that aren't yet in Immich get uploaded on service start, then deleted locally.
- **Dockerised.** Multi-arch image on GHCR; single `docker compose up -d`.

## Architecture

Two binaries:

- `frameio-auth` — runs once, interactive. Starts a local HTTPS server on `https://localhost:12345`, prints an Adobe IMS authorization URL, captures the redirect, exchanges the code for access + refresh tokens, writes `tokens.json`. Run it on your workstation; copy `tokens.json` to the deployment host.
- `frameio-relay` — the always-on service. Reads `tokens.json`, registers the webhook, listens on `:9000/webhook`, processes events, runs reconcile polling, uploads to Immich.

Refresh tokens last months; access tokens are refreshed 60 seconds before expiry automatically.

## Prerequisites

- A Frame.io account with a Camera-to-Cloud-enabled project. Free tier works.
- A running Immich instance reachable over HTTPS.
- Docker + Docker Compose on the host that'll run the relay.
- A publicly-reachable HTTPS endpoint for webhook delivery. Recommended: [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) (free, no port forwarding, no TLS config). Alternatives: Cloudflare Tunnel, ngrok, or a real public IP + Caddy/Let's Encrypt.
- An Adobe Developer Console account (free) to register an OAuth app — Frame.io V4 doesn't support personal access tokens.

## Setup

### 1. Register an Adobe OAuth app

1. Go to https://developer.adobe.com/console → **Create new project**.
2. **Add API → Frame.io V4 API**.
3. Credential type: **OAuth Web App**.
4. **Default redirect URI**: `https://localhost:12345/callback`
5. **Redirect URI pattern**: `https://localhost:12345/.*`
6. Note the **Client ID** and **Client Secret**.

### 2. Generate tokens on your workstation

```sh
make build
./bin/frameio-auth \
  -client-id <CLIENT_ID> \
  -client-secret <CLIENT_SECRET>
```

Open the URL it prints in your browser, grant access, click past the self-signed-cert warning (the cert is locally generated and thrown away when the process exits). `tokens.json` will appear in the current directory. Copy it to the deployment host as `data/tokens.json`.

### 3. Find the Frame.io IDs you'll need

`frameio-auth` prints the full Frame.io hierarchy (accounts → workspaces → projects) at the end of the first run. If you have exactly one of each, it also prints a ready-to-paste `.env` block:

```
Discovered Frame.io hierarchy:

  Account: Zack's Account
    id: 4668420c-6e47-43e1-969f-71c66e2aae07
    Workspace: Zack's Workspace
      id: 684071df-1816-4b7d-ae5e-d6fb455c8b8d
      Project: Zack's First Project
        id: 79ee151b-ce4f-4fe6-a00c-cfa59471e50f
        root_folder_id: fe56bed4-ddd9-4dd0-81be-ca1c4e834df5

Exactly one account / workspace / project — copy these into your .env:

  FRAMEIO_ACCOUNT=4668420c-6e47-43e1-969f-71c66e2aae07
  FRAMEIO_WORKSPACE=684071df-1816-4b7d-ae5e-d6fb455c8b8d
  FRAMEIO_FOLDER=fe56bed4-ddd9-4dd0-81be-ca1c4e834df5
```

Re-run discovery any time (e.g. after creating a new project) without re-authenticating:

```sh
./bin/frameio-auth -discover -tokens data/tokens.json
```

### 4. Generate an Immich API key

In Immich web UI → **User Settings → API Keys → New API Key**. Select only:

- `asset.read`
- `asset.upload`

Nothing else is required.

### 5. Set up a public HTTPS endpoint

Easiest option, Tailscale Funnel:

```sh
sudo tailscale up            # one-time, if not already authenticated
sudo tailscale funnel --bg 9000
tailscale funnel status      # prints the public URL
```

Note the `https://<host>.<tailnet>.ts.net/` URL. The webhook path is `/webhook`, so the full value for `FRAMEIO_PUBLIC_URL` will be `https://<host>.<tailnet>.ts.net/webhook`.

### 6. Configure and run

Clone the repo onto the deployment host, copy `.env.example` to `.env`, fill in:

```
FRAMEIO_PUBLIC_URL=https://<host>.<tailnet>.ts.net/webhook
IMMICH_URL=https://immich.example.com
IMMICH_API_KEY=<key from step 4>
# FRAMEIO_ACCOUNT / FRAMEIO_WORKSPACE / FRAMEIO_FOLDER can be omitted
# if you have exactly one account + one workspace + one project;
# the relay will auto-discover them at startup.
```

Place `tokens.json` (from step 2) at `./data/tokens.json`. Then:

```sh
docker compose up -d
docker compose logs -f frameio-relay
```

You should see:

```
authenticated as <your name>
Immich integration enabled: https://immich.example.com
registered webhook <uuid> → https://<host>.<tailnet>.ts.net/webhook
webhook server listening on :9000 (path /webhook)
```

Take a photo, trigger the Frame.io upload on the camera. Within a second of the upload completing, the log should show:

```
webhook: file.upload.completed resource=file/<uuid>
[<uuid>] DSCF1234.JPG (image/jpeg, 12345678 bytes) → /downloads/2026/04-22/DSCF1234.JPG
[<uuid>] immich uploaded: <immich asset uuid>
[<uuid>] deleted from frame.io
```

## Environment variables

All configurable via env vars (suitable for Docker Compose) or CLI flags.

| Variable | Flag | Required | Default | Description |
|---|---|---|---|---|
| `FRAMEIO_ACCOUNT` | `-account` | auto | | Frame.io V4 account UUID. Auto-discovered at startup if exactly one account is on this user. |
| `FRAMEIO_WORKSPACE` | `-workspace` | auto | | Frame.io V4 workspace UUID. Auto-discovered if exactly one workspace is in the account. |
| `FRAMEIO_FOLDER` | `-folder` | auto | | Project root folder UUID; reconcile walks this recursively. Auto-discovered if exactly one project is in the workspace. |
| `FRAMEIO_PUBLIC_URL` | `-public-url` | recommended | | Public HTTPS endpoint where Frame.io delivers webhooks (path must be `/webhook`). Omit to run in polling-only mode. |
| `IMMICH_URL` | `-immich-url` | | | Immich base URL, e.g. `https://immich.example.com`. Empty disables Immich integration (files land only on local disk). |
| `IMMICH_API_KEY` | `-immich-key` | if immich-url set | | Immich API key. |
| `FRAMEIO_STUCK_TIMEOUT` | `-stuck-timeout` | | `0` (disabled) | Delete non-ready Frame.io files older than this duration. Frame.io does not garbage-collect abandoned uploads, so stuck files eat your quota forever. Typical value: `6h`. |
| | `-tokens` | | `tokens.json` | Path to tokens file from `frameio-auth`. |
| | `-state` | | `relay-state.json` | Local state (webhook registration data). |
| | `-out` | | `downloads` | Temporary local buffer for downloaded files. |
| | `-webhook-addr` | | `:9000` | Webhook receiver bind address. |
| | `-poll` | | `60s` | Reconcile polling interval. |
| | `-dry-run` | | `false` | Download but don't delete from Frame.io or upload to Immich. |

## Running outside Docker

```sh
make build
./bin/frameio-relay \
  -tokens tokens.json \
  -account <acct> \
  -workspace <ws> \
  -folder <root> \
  -public-url https://<your-tunnel>/webhook \
  -immich-url https://immich.example.com \
  -immich-key <key>
```

## Troubleshooting

**`invalid_scope` at OAuth time.** Adobe changed scope names. The correct list is `openid email profile offline_access additional_info.roles` — no Frame.io-specific scope is needed.

**`Unable to validate entity` from Adobe.** Redirect URI mismatch. Adobe rejects raw IPs like `127.0.0.1` even for loopback; use `localhost` instead.

**Webhook fires but signature verification fails.** Check for stale webhooks on your Frame.io workspace — if you've run the relay multiple times with different state files, you may have duplicate registrations with different secrets. List them: `curl -H "Authorization: Bearer $ACCESS" https://api.frame.io/v4/accounts/$ACCT/workspaces/$WS/webhooks`, delete stale ones via `DELETE /v4/accounts/$ACCT/webhooks/$ID`.

**Files on Frame.io stuck with `status: created`.** Bytes haven't finished uploading, or the upload from camera failed. Frame.io doesn't auto-clean these and they'll eat your storage quota indefinitely. Set `FRAMEIO_STUCK_TIMEOUT=6h` (or whatever grace period is longer than your slowest realistic upload) and the relay will delete any file stuck in a non-ready state past that age during its reconcile pass.

**`403 AccessDenied` on file download.** The file's pre-signed S3 URL was issued but the bytes aren't on S3 yet. Happens if you treat `status: created` as downloadable. The relay handles this by only accepting `uploaded`/`transcoded`/equivalent statuses.

**Immich says `duplicate` for every file.** That's fine — Immich's SHA-1 dedup caught them. The relay correctly proceeds to delete from Frame.io and the local copy; no state corruption.

**Relay keeps seeing the same file on restart.** Check that your deployment user can write to `data/tokens.json` and `data/relay-state.json`. The container runs as uid 1000 by default (see `docker-compose.yml`).

## Security notes

- `tokens.json` contains a long-lived OAuth refresh token; treat it like a password. 0600 on disk, exclude from backups/sharing.
- `relay-state.json` contains the webhook signing secret. Same treatment.
- `.env` contains Client Secret + Immich API key. Do not commit; `.gitignore` covers it.
- Frame.io's download URLs are pre-signed with short (~1h) expiry. Not a leak risk in logs if we log the Frame.io file ID only — which we do.

## Limitations

- Depends on Frame.io's continued free tier for the transit relay. If Adobe changes storage quotas, delete-after-download keeps usage near zero as long as the relay is running.
- Webhook delivery requires a public HTTPS endpoint. Polling-only mode works without it but adds up to one polling interval of latency per file.
- Frame.io V4 personal accounts cannot use OAuth Server-to-Server; user-flow OAuth is the only option, which means one interactive browser login to bootstrap. Refresh tokens handle steady-state.
- Immich's SHA-1 dedup is file-content based, so multiple Frame.io uploads of the same photo won't create duplicates in Immich. But a photo edited on-camera then re-uploaded will have different bytes and be ingested as a new asset.

## License

MIT.
