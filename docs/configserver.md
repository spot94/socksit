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
  rotate the signing key, view the audit log, configure LDAP. Two roles —
  **Administrator** (everything) and **Operator** (routing only) — see
  [Authentication & roles](#authentication--roles) below.

Each **profile** is an independent feed at its own URL (e.g. `team-a`, `team-b`)
with its own app set — different groups get different configs. All profiles are
signed by the one server key.

The served config carries only **routing** fields (proxy address/port/udp, apps,
mode, kill-switch, direct subnets). Kill-switch and Proxy UDP are **tri-state** on
the server: `on`/`off` force the value and lock that toggle on clients, while
`user-defined` leaves the field out of the feed so each client controls it. It
never carries the SOCKS
**credentials** (those stay on each client, DPAPI-encrypted) or client-local
policy like `config_source`/`update`. Feeds are validated with the *exact* client
schema (`internal/config`) before signing, so a client can never receive an
invalid config.

## Run (Docker)

By default the compose **pulls the image from GHCR**
(`ghcr.io/spot94/socksit-configserver:latest`), built by
`.github/workflows/configserver-image.yml` on every push to `main` (`:latest`) and
on version tags (`:X.Y.Z`). GHCR packages start private — after the first push,
make the package public (repo → Packages → Package settings → visibility) or run
`docker login ghcr.io` on the host.

```bash
cd deploy/configserver
cp .env.example .env.dev          # set ADMIN_PASSWORD or leave empty for first-run
docker compose -f docker-compose.yml -f docker-compose.dev.yml --env-file .env.dev up -d
# → http://127.0.0.1:8080  (pull_policy: always keeps :latest fresh)
```

Production (behind a TLS reverse proxy on an external `edge` network):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.prod up -d
```

Pin a version with `CONFIGSERVER_IMAGE=ghcr.io/spot94/socksit-configserver:0.1.5`
in the env file.

To **build the image locally** instead of pulling (the build context is the repo
root — the server shares `internal/config` with the client), add the build
override and pass `--build`:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml -f docker-compose.dev.yml --env-file .env.dev up -d --build
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

## Authentication & roles

There are two ways to sign in and two roles:

- **Local administrator** — the bootstrap account from first-run (always available,
  cannot be disabled). Always has the **Administrator** role.
- **LDAP** — optional, configured in the **LDAP** section of the admin UI (only the
  local admin, or an LDAP administrator, can open it). Meant for Active Directory.

**Roles.**

| | Administrator | Operator |
|---|---|---|
| Edit profiles (proxy/apps/subnets/mode/kill-switch) | ✓ | ✓ |
| Signing-key generate/import/rotate | ✓ | — |
| Per-profile **Migration** block | ✓ | — |
| Audit log | ✓ | — |
| LDAP configuration | ✓ | — |

The Operator restrictions are enforced **server-side** (the key/audit/LDAP endpoints
require the Administrator role → `403`; a Save from an operator keeps the profile's
existing migration untouched), and mirrored in the UI (those nav items and the
migration editor are hidden). The local admin is always an Administrator, so an
LDAP misconfiguration can never lock you out of key/LDAP management.

### LDAP setup (Active Directory)

Open **LDAP** in the sidebar (Administrator only) and fill in:

| Field | Example | Notes |
|-------|---------|-------|
| Enabled | on | when on, the login page shows an **LDAP** tab next to **Local admin** |
| URL | `ldaps://dc.corp.local:636` | `ldap://` or `ldaps://`; StartTLS toggle for `ldap://:389` |
| Skip TLS verify | off | only for lab CAs; leave off in prod |
| Bind DN / password | `CN=svc-socksit,OU=Svc,DC=corp,DC=local` | a **service account** used to search for users; the password is write-only (never returned by the API) |
| Base DN | `DC=corp,DC=local` | subtree searched for the user |
| User filter | `(sAMAccountName={user})` | must contain `{user}` — replaced (escaped) with the typed username |
| Administrator filter | `(memberOf=CN=SocksIt-Admins,OU=Groups,DC=corp,DC=local)` | matched against the found user's own entry |
| Operator filter | `(memberOf=CN=SocksIt-Operators,OU=Groups,DC=corp,DC=local)` | matched the same way |
| Display attribute | `displayName` | shown next to **Log out** for LDAP users |

Login flow (service-account bind): the server binds as the service account, searches
Base DN with the user filter, **re-binds as the user** to verify the password, then
decides the role — Administrator filter first, else Operator filter; a user matching
neither is refused. **Test connection** does a service bind without touching a user.

The LDAP config (including the bind password) is stored in `ldap.json` on the `/data`
volume (`0600`) — treat that volume as secret. Failed LDAP logins share the same
per-IP brute-force lockout as the local login. The signed-in identity (local admin
name or LDAP `displayName`, plus a role badge) is shown next to **Log out**.

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
     # proxy: ""           # how to reach the feed; empty = direct (default). The feed
                           # must NOT go through the SOCKS proxy it configures — leave
                           # this empty unless the config server is only reachable via a proxy.
   ```

Clients fetch on start and on their interval, verify the signature against
`pubkey`, and apply it. Rotating the key re-signs every profile — update every
client's `pubkey` afterwards.

## Migration (server moved / key rotation)

Each profile has an optional **Migration** block, served as a signed
`migrate.yaml` sidecar next to the config. It lets you push channel changes to
clients centrally instead of reconfiguring each one:

- **New config URL** — when the server moves. Clients apply it automatically; the
  pinned key still guards them (a wrong/hostile URL can't forge a valid config,
  worst case is a failed fetch), so no per-client approval is needed.
- **Apply mode** (replace / override) — dictate whether clients take exactly this
  config (replace) or keep their own apps/subnets on top (override). Applied
  automatically.
- **Update endpoint / channel / mode** — applied automatically too; app binaries
  are still verified against the app's built-in update key, so a bad endpoint
  can't push a malicious binary.
- **Rotate trusted key (new pubkey)** — moves the root of trust, so it is **never**
  applied silently. Each client surfaces it in the panel for the local admin to
  Accept or Decline; declined keys aren't re-prompted.

Simple key rotation: put the *new* public key in the migration while the server
still signs with the *current* key, let clients Accept it, then switch the
server's signing key (Generate/Import). Clearing all migration fields removes the
sidecar. Migration only reaches clients new enough to understand it; the routing
feed itself stays backward-compatible.

## Security notes

- The **private signing key** lives on the `/data` volume (`0600`), never in git
  or the image (SEC-1). Back it up out-of-band; losing it means clients pinned to
  its public key stop accepting new configs until you distribute a new pubkey.
- The image is distroless/non-root; the admin surface requires auth (ADM-1) and
  every admin action is written to an audit log (SEC-3).
- Put a TLS-terminating reverse proxy in front for anything beyond local dev; set
  `SECURE_COOKIES=true` there and forward `X-Forwarded-Proto`.
