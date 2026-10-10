# Cloudflare Subdomain Bridge

**API-only, self-hosted Cloudflare permissions bridge** (V1 alpha). Each client receives a dedicated bearer key and a hostname scope. A single upstream Cloudflare API token remains inside the bridge. The bridge offers only narrowly defined operations rather than forwarding arbitrary Cloudflare API requests.

> **Release status:** The source builds and passes offline mocked-Cloudflare tests. It has **not** been end-to-end tested against a live Cloudflare account. Treat this as a preview; use a test zone before production deployment, especially for Worker routes, tunnels, and email.

## Features

- Environment-defined clients, keys, subdomain scopes, descendant and capability permissions. Startup rejects invalid/overlapping scopes and duplicate keys.
- DNS: list/get/create/replace/delete A, AAAA, CNAME, TXT and MX records within scope. Does not allow wildcard names. Accepts `_acme-challenge` names.
- Tunnels: create dedicated remotely managed Cloudflare tunnels; get connection token; add/list/remove scoped HTTP(S) public hostnames (and their DNS CNAMEs); delete empty tunnels. Never exposes private-network routing, warp, or arbitrary tunnel settings.
- Workers: deploy small JavaScript module Workers; disable workers.dev and preview URLs; update script code; route Worker to an exact approved hostname; list/remove own routes and Workers. This is intentionally *not* full Wrangler compatibility (no bindings, assets or advanced Worker configs).
- Email Routing: list/create/delete exact-address rules using Cloudflare's `drop`, `forward` (verified destinations only), or an owned Email Worker. No catch-all support, no automatic destination verification.
- `/docs`: built-in self-documenting interactive API browser, no external CDN dependencies. `/openapi.json`: OpenAPI 3.1. `/healthz`: process health. `/api/v1/me`: current client scope.
- Local SQLite metadata/audit trail for **ownership of Workers, routes, tunnels, and email rules**. Client credentials stay in the environment, not SQLite.

## Install using Docker Compose

```bash
mkdir -p /opt/cloudflare-bridge
cd /opt/cloudflare-bridge
# Unzip this repository's files into this directory.
cp .env.example .env
chmod 600 .env
# Edit .env to use valid Cloudflare credentials, zone and client scopes.
mkdir -p data
sudo chown 10001:10001 data
sudo chmod 700 data
docker compose up -d --build
docker compose logs --tail=50
```

By default Compose publishes the bridge on **127.0.0.1:8080** (host-loopback only), then you publish through your existing reverse proxy with HTTPS/mTLS or an authenticated private network. **The raw listener is plaintext HTTP**, and the documentation page can submit API calls using locally entered client credentials, so use HTTPS when opening it and **never expose the raw HTTP listener to the public Internet**. Set `BRIDGE_HOST_BIND=0.0.0.0` in `.env` only if you deliberately want the plaintext listener on every host interface.

### Mandatory environment variables

```dotenv
CF_API_TOKEN=your_scoped_cloudflare_api_token
CF_ACCOUNT_ID=your_cloudflare_account_id
CF_ZONE_ID=your_cloudflare_zone_id
CF_ZONE_NAME=example.com
BRIDGE_LISTEN_ADDR=0.0.0.0
BRIDGE_HOST_BIND=127.0.0.1
BRIDGE_PORT=8080
BRIDGE_DATA_DIR=/data
BRIDGE_RATE_PER_MIN=120
BRIDGE_CLIENT_HERMES='{"key":"64_PLUS_RANDOM_HEX_CHARACTERS","scope":"hermes.example.com","descendants":true,"permissions":["dns","workers","tunnels","email"]}'
BRIDGE_CLIENT_MAILMOOSE='{"key":"ANOTHER_LONG_UNIQUE_RANDOM_KEY","scope":"mail.example.com","descendants":true,"permissions":["dns","email"]}'
```

- `BRIDGE_LISTEN_ADDR` is the **container listener bind host** (bare host, for example `0.0.0.0`, **not** a `host:port` string). Under Compose leave it at `0.0.0.0` so the published port can reach the process. `BRIDGE_HOST_BIND` is the **host interface** Compose binds the published port to (`127.0.0.1` by default). The listen port comes from `BRIDGE_PORT` (default `8080`). When running the binary directly (no Docker), `BRIDGE_LISTEN_ADDR` is the actual listener host and `BRIDGE_HOST_BIND` is unused.
- `CF_ZONE_NAME` is needed to validate the subdomain boundary, in addition to the zone ID.
- `BRIDGE_CLIENT_*` clients are defined **entirely** in `.env`. Every API key should be unique, unpredictable and at least 24 bytes; generate with `openssl rand -hex 32`. Changing clients/permissions requires `docker compose up -d --force-recreate`.
- `descendants:false` allows the exact hostname only; `true` includes subordinate names such as `app.hermes.example.com`. **Overlapping assignments are rejected.**
- Permission strings: `dns`, `workers`, `tunnels`, `email`. Omitted permissions default to denied.
- Underlying Cloudflare API token needs appropriate account/zone-specific permissions for the modules enabled: Zone DNS Edit/Read, Account Cloudflare Tunnel Edit/Read, Workers Scripts Edit/Read, Workers Routes Edit/Read, and Zone Email Routing Rules Edit/Read (labels may differ in Cloudflare dashboard). Prefer a scoped token over a legacy Global API key. Create the token using Cloudflare's UI; it never leaves the bridge.

### Example requests

```bash
export BRIDGE_URL='http://127.0.0.1:8080'
export CLIENT_KEY='your_own_client_key'
curl -sS -H "Authorization: Bearer $CLIENT_KEY" "$BRIDGE_URL/api/v1/me"
curl -sS -H "Authorization: Bearer $CLIENT_KEY" "$BRIDGE_URL/api/v1/dns"

curl -sS -X POST "$BRIDGE_URL/api/v1/dns" \
  -H "Authorization: Bearer $CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"app.hermes.example.com","type":"A","content":"192.0.2.50","ttl":1,"proxied":false}'

curl -sS -X POST "$BRIDGE_URL/api/v1/tunnels" \
  -H "Authorization: Bearer $CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"origin"}'

# Then GET /api/v1/tunnels/<id>/token and install cloudflared on the origin.
# POST /api/v1/tunnels/<id>/hostnames
# {"hostname":"app.hermes.example.com","service":"http://localhost:8080"}
```

Browse `http://127.0.0.1:8080/docs` for the full interactive endpoint list or use `/openapi.json` for client generation. Generated docs are committed as `openapi.json`; edit/generate them with `python3 make_spec.py` when changing endpoints.

## Behaviour and operational limits

- This is a **subdomain API permission boundary**, not a separate Cloudflare account or native zone. A trusted server administrator with container/env access still holds the privileged Cloudflare token. All clients are able to deploy executable Worker code to their own Workers. Worker script execution is not confined to a particular subdomain; *Worker route assignment* is scoped.
- **One Cloudflare account and zone per bridge instance.** No administrator control API. All ownership records persist under `./data/bridge.db`. Back up `./data` and `.env` separately and securely. Losing SQLite ownership data makes previously provisioned resources unmanaged; there is no automatic takeover/reconciliation.
- Cloudflare creates DNS records for tunnel hostnames and the bridge tracks them to prevent normal DNS mutation. Unexpected direct Cloudflare changes lead to drift errors in certain operations; manual reconciliation may be necessary.
- **DNS changes are immediate.** Creating a record (`POST /api/v1/dns`) is existence-guarded: if the name already holds any DNS record the request is rejected with `409` rather than adding a second entry. `PATCH /api/v1/dns/{id}` still replaces an existing record within the client's assigned namespace, so create scope boundaries appropriately. Deleting a DNS record doesn't remove an associated Worker route that was set independently.
- Email Routing must already be **enabled and configured** for a particular subdomain in Cloudflare (including any required MX); forwarding addresses must already be verified by Cloudflare. Cloudflare does not support catch-all routing for subdomains. Some Email Routing configurations require Cloudflare dashboard setup not implemented here.
- A Worker `hostname/*` route requires a suitable proxied DNS record for the hostname. Only exact hostname patterns are allowed by the bridge. These are Worker Routes, **not** Worker Custom Domains.
- Deep subdomains such as `app.hermes.example.com` may require additional TLS certificate coverage (for example Advanced Certificate Manager/Total TLS). The bridge does not issue/validate certificates.
- Remotely managed tunnels support HTTP and HTTPS origins in V1. For service origins, `localhost` means the host running **cloudflared**, not the bridge. Tunnel connector tokens are powerful: keep them secret and rotate/recreate the tunnel if exposed.
- No high-availability: concurrent deployments of multiple bridge instances backed by the same SQLite DB are not supported. Operations spanning Cloudflare and SQLite are not atomic; if Cloudflare succeeds and SQLite fails, manually reconcile resource ownership. Back up before upgrades.
- One in-memory per-client request limit (`BRIDGE_RATE_PER_MIN`, default 120) is provided, but use upstream Cloudflare rate quotas, a reverse proxy and network controls for production.

## Testing

Local Go 1.23+ compiler and SQLite development headers are needed to run from source:

```bash
go test ./...
go vet ./...
CGO_ENABLED=1 go build -o bridge .
```

Tests use `httptest` to simulate Cloudflare, exercising authentication, configuration conflicts, DNS scope boundaries, Worker and Email ownership, tunnel token isolation and SQLite persistence. There are **no live Cloudflare acceptance tests** in this ZIP.

## License

MIT; see `LICENSE`.
