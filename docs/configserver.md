# SocksIt Config Server

The server half of SocksIt's managed-config channel. It hosts **signed
`socksit.yaml` feeds** that clients pull (`config_source`), and an **authenticated
web admin** to edit those feeds and manage the **Ed25519 signing key**. It runs as
a Docker container; TLS is terminated by a reverse proxy in front (no TLS in the
container itself).

## What it does

- **Public feed (no auth, integrity via signature):**
  - `GET /configs/<profile>/socksit.yaml`
  - `GET /configs/<profile>/socksit.yaml.sig`
  - `GET /healthz`
- **Admin (login required):** create/edit/delete named profiles, generate/import/
  rotate the signing key, view the audit log.

Each **profile** is an independent feed at its own URL (e.g. `team-a`, `team-b`)
with its own app set — different groups get different configs. All profiles are
signed by the one server key.

The served config carries only **routing** fields (proxy address/port/udp, apps,
mode, kill-switch, direct subnets, fake-ip). It never carries the SOCKS
**credentials** (those stay on each client, DPAPI-encrypted) or client-local
policy like `config_source`/`update`. Feeds are validated with the *exact* client
schema (`internal/config`) before signing, so a client can never receive an
invalid config.

## Run (Docker)

Build context is the repo root (the server shares `internal/config` with the
client).

```bash
cd deploy/configserver
cp .env.example .env.dev          # set ADMIN_PASSWORD or leave empty for first-run
docker compose -f docker-compose.yml -f docker-compose.dev.yml --env-file .env.dev up -d --build
# → http://127.0.0.1:8080
```

Production (behind a TLS reverse proxy on an external `edge` network):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

`dev` / `test` / `prod` each use their own env file, volume and password so they
stay independent.

### Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `LISTEN` | `:8080` | listen address |
| `DATA_DIR` | `/data` | volume for key, profiles, admin, audit |
| `ADMIN_PASSWORD` | – | bootstrap admin on first run; empty → set via first-run page |
| `SECURE_COOKIES` | `false` | `true` only behind TLS (prod) |
| `IDLE_TIMEOUT` | `30m` | session inactivity timeout |

## First-run

Open the URL. If `ADMIN_PASSWORD` was set, log in with it; otherwise the first-run
page prompts you to create the admin password (min 10 chars). Sessions are
cookie-based (HttpOnly, SameSite=Strict, Secure in prod) with CSRF tokens on
mutating requests and brute-force lockout on the login.

## Set up a feed

1. **Signing key** → *Generate new key* (or *Import* a key from `mksign genkey`).
   Copy the shown **public key**.
2. **Profiles** → *New profile*, fill in proxy/apps/mode/…, **Save & sign**.
3. Copy the **Client snippet** and put it in each client's `socksit.yaml`:

   ```yaml
   config_source:
     url: https://<your-host>/configs/team-a/socksit.yaml
     pubkey: <public key from step 1>
     signed: true
     merge: replace        # or override
   ```

Clients fetch on start and on their interval, verify the signature against
`pubkey`, and apply it. Rotating the key re-signs every profile — update every
client's `pubkey` afterwards.

## Security notes

- The **private signing key** lives on the `/data` volume (`0600`), never in git
  or the image (SEC-1). Back it up out-of-band; losing it means clients pinned to
  its public key stop accepting new configs until you distribute a new pubkey.
- The image is distroless/non-root; the admin surface requires auth (ADM-1) and
  every admin action is written to an audit log (SEC-3).
- Put a TLS-terminating reverse proxy in front for anything beyond local dev; set
  `SECURE_COOKIES=true` there and forward `X-Forwarded-Proto`.
