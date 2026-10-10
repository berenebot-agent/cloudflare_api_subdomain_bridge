# Cloudflare Subdomain Bridge

**Give agents a Cloudflare API key that can only touch what you let it.**

You want an AI agent, script, or teammate to manage DNS, tunnels, Workers, or
email routing — but handing over your Cloudflare API token means handing over
your **entire account**. The bridge sits in the middle: one privileged upstream
token stays locked inside, and each client gets its own bearer key scoped to
**one subdomain and only the services you approve**. Everything else is refused
at the edge.

> **V1 alpha — preview.** Builds and passes offline mocked-Cloudflare tests, but
> has **not** been end-to-end tested against a live account. Try it on a test
> zone first, especially for Workers, tunnels, and email.

![Agent requests go through the bridge: permitted subdomains pass, unrelated domains are blocked](docs/api-access-flow.png)

*Example: a client scoped to `hermes.example.com` may manage `app.hermes.example.com`, but not `other.example.com`.*

## Why it exists

- **Least privilege by default.** A client scoped to `hermes.example.com` cannot
  touch `mail.example.com`, other zones, or unrelated services.
- **No raw token sprawl.** Only the bridge holds the Cloudflare credential;
  clients never see it and it is never logged.
- **Narrow operations, not a proxy.** Clients can list/create/delete DNS records,
  manage their own tunnels, deploy small Workers, and configure exact-address
  email rules — not arbitrary Cloudflare API calls.
- **Auditable ownership.** A local SQLite ledger tracks which Workers, routes,
  tunnels, and email rules the bridge provisioned, and blocks out-of-band drift.
- **Self-hosted, single container.** No SaaS middleman, no external CDN.

## What each client can do

Permissions are opt-in per client (`dns`, `workers`, `tunnels`, `email`):

- **DNS** — list/get/create/replace/delete `A`, `AAAA`, `CNAME`, `TXT`, `MX`
  records inside scope. Wildcards rejected; `_acme-challenge` allowed.
- **Tunnels** — create remotely managed Cloudflare tunnels, fetch connection
  tokens, map scoped public hostnames (+ their DNS CNAMEs), delete empty tunnels.
  No private-network routing or arbitrary tunnel config.
- **Workers** — deploy small JS module Workers, update code, and route to an exact
  approved hostname. Not full Wrangler compatibility (no bindings/assets).
- **Email Routing** — list/create/delete exact-address rules (`drop`, `forward`
  to verified destinations, or an owned Email Worker). No catch-alls.

Plus `/docs` (built-in interactive API browser), `/openapi.json` (OpenAPI 3.1),
`/healthz`, and `/api/v1/me`.

## Quick start (Docker Compose)

```bash
mkdir -p /opt/cloudflare-bridge && cd /opt/cloudflare-bridge
# Unzip the repository files here, then:
cp .env.example .env
chmod 600 .env

# Edit .env: real Cloudflare credentials + at least one client.
# Generate each client key with:  openssl rand -hex 32

mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data
docker compose up -d --build
docker compose logs --tail=50
```

Compose publishes on **127.0.0.1:8080** by default. Front it with HTTPS or an
authenticated private network — the listener itself is plaintext HTTP.

### Minimum `.env`

```dotenv
CF_API_TOKEN=your_scoped_cloudflare_api_token
CF_ACCOUNT_ID=your_cloudflare_account_id
CF_ZONE_ID=your_cloudflare_zone_id
CF_ZONE_NAME=example.com

BRIDGE_LISTEN_ADDR=0.0.0.0     # container bind host (bare host, not host:port)
BRIDGE_HOST_BIND=127.0.0.1     # host interface Compose publishes on
BRIDGE_PORT=8080
BRIDGE_DATA_DIR=/data

# JSON: key + subdomain scope + which modules this client may use
BRIDGE_CLIENT_HERMES='{"key":"<openssl rand -hex 32>","scope":"hermes.example.com","descendants":true,"permissions":["dns","workers","tunnels","email"]}'
BRIDGE_CLIENT_MAIL='{"key":"<another long random key>","scope":"mail.example.com","descendants":true,"permissions":["dns","email"]}'
```

- `descendants:true` allows the host **and** subdomains (`app.hermes.example.com`);
  `false` allows the exact host only. Overlapping scopes are rejected at startup.
- Clients live **only** in `.env`. Changing them needs
  `docker compose up -d --force-recreate`. There is no admin API.
- Upstream token needs, per enabled module: Zone DNS + Zone Read, Workers Routes,
  Email Routing Rules (zone) and Cloudflare Tunnel + Workers Scripts (account).
  Prefer a scoped API token over a Global key.

### Run from source (no Docker)

Go is not required on the host in this repo — the wrapper runs the same image as
the Dockerfile:

```bash
./cloudflare-go.sh test ./...
./cloudflare-go.sh vet ./...
./cloudflare-go.sh build -o bridge .
BRIDGE_LISTEN_ADDR=127.0.0.1 BRIDGE_PORT=8080 \
  BRIDGE_CLIENT_HERMES='{"key":"...","scope":"hermes.example.com","descendants":true,"permissions":["dns"]}' \
  CF_API_TOKEN=... CF_ACCOUNT_ID=... CF_ZONE_ID=... CF_ZONE_NAME=example.com \
  ./bridge
```

With a local Go 1.23+ toolchain and SQLite dev headers, the equivalent is
`go test ./...`, `go vet ./...`, `CGO_ENABLED=1 go build -o bridge .`.

### Try it

```bash
export BRIDGE_URL='http://127.0.0.1:8080'
export CLIENT_KEY='your_own_client_key'
curl -sS -H "Authorization: Bearer $CLIENT_KEY" "$BRIDGE_URL/api/v1/me"

curl -sS -X POST "$BRIDGE_URL/api/v1/dns" \
  -H "Authorization: Bearer $CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"app.hermes.example.com","type":"A","content":"192.0.2.50","ttl":1,"proxied":false}'
```

Open `http://127.0.0.1:8080/docs` for the full endpoint list.

## Things to know before production

- **This is a permission boundary, not a separate account.** A host admin with
  env access still holds the real token. Worker *code* is executable — only
  *route assignment* is scoped.
- **One account + one zone per instance.** No admin API. Back up `./data` and
  `.env`; losing the SQLite ledger orphans previously provisioned resources.
- **Cloudflare is live state, SQLite is the ledger.** Some operations read live
  state and return `409` on drift; manual reconciliation may be needed.
- **DNS changes are immediate.** Conflicting creates are rejected (`409`);
  `PATCH` replaces a record within the client's namespace — size scopes carefully.
- **Email Routing** must already be enabled/configured (including MX) and
  destinations verified in Cloudflare; no catch-all support.
- **Worker routes** need a suitable proxied DNS record and are Routes, not
  Custom Domains. Deep subdomains may need extra TLS coverage (the bridge issues
  no certs).
- **Tunnel connector tokens are powerful** — keep them secret and rotate on
  exposure. `localhost` in a service origin means the `cloudflared` host.
- **No HA / not atomic.** No concurrent instances on one DB; Cloudflare→SQLite
  steps can partially fail. Back up before upgrades.
- Only a simple in-memory per-client rate limit (`BRIDGE_RATE_PER_MIN`, default
  120) — use Cloudflare quotas and a reverse proxy in production.

## Testing

Tests are hermetic: `httptest` stands in for the Cloudflare API and exercises
auth, config conflicts, DNS scope boundaries, Worker/Email ownership, tunnel
token isolation, and SQLite persistence. There are **no live acceptance tests**.

```bash
./cloudflare-go.sh test ./...
```

## License

MIT; see `LICENSE`.
