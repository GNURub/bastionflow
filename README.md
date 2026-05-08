# BastionFlow

> A private, production-minded CrowdSec operations dashboard for Traefik stacks.
>
> Visualize attacks in real time, inspect decisions, manage bans/unbans, configure edge rate limits, and send notifications to Slack, Discord or generic webhooks.

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)
![CrowdSec](https://img.shields.io/badge/CrowdSec-1.7-orange.svg)
![Traefik](https://img.shields.io/badge/Traefik-3.6-blue.svg)

---

## What you get

```text
Browser
  │
  ▼
Traefik :8080
  ├─ CrowdSec bouncer middleware
  ├─ Edge Gate auth/challenge middleware
  ├─ Rate limit middleware
  │
  ├─ bastionflow.localhost  ──► Dashboard
  └─ whoami.localhost          ──► Protected test app

CrowdSec reads Traefik access logs and creates alerts/decisions.
The dashboard reads CrowdSec LAPI, Traefik logs and local SQLite state.
Optional worker sends notifications even when the dashboard tab is closed.
Runtime: Bun + bun:sqlite.
```

### Main features

- Live CrowdSec overview: alerts, decisions, machines, bouncers and metrics.
- Real-time attack map with directional arcs.
- Live HTTP/event feed with method, host, path, service, status and scenario.
- IP intelligence page with actions: ban, unban and allowlist.
- Decisions page with create/delete operations.
- Dynamic edge rate limits by IP, path or service.
- Edge Gate browser/password challenge for protected routes.
- Optional background notifications: Slack, Discord and generic webhook.
- SQLite persistence for dashboard settings, notification channels, allowlists, rate-limit rules and IP enrichment cache.
- No fake dashboard data: if CrowdSec is unavailable, the UI shows partial/empty real state.

---

## Use the published Docker image

Once you publish the image, users do **not** need to build the dashboard from source.

Set the image name in `.env` or in your shell:

```env
CROWDSEC_PANEL_IMAGE=ghcr.io/gnurub/bastionflow:latest
```

Then run the production compose file:

```bash
cp .env.example .env
# edit .env and set your CrowdSec URL, credentials and secrets

docker network create crowdsec-internal || true
docker compose up -d
```

With background notifications:

```bash
docker compose --profile notifications up -d
```

The same image is used for both roles:

| Container | Command |
| --- | --- |
| `bastionflow` | default Next.js server, `bun server.js` |
| `bastionflow-notification-worker` | `bun scripts/notification-worker.mjs` |

> Official image path: `ghcr.io/gnurub/bastionflow`. Forks can override `CROWDSEC_PANEL_IMAGE` with their own image.


---

## Integrate with an existing Traefik v3 stack

Use this section when you already have a Docker Compose project with Traefik v3 and you only want to add BastionFlow to it.

### Target architecture

```text
Your existing Docker network
  ├─ traefik
  ├─ crowdsec
  ├─ your apps
  ├─ bastionflow
  └─ bastionflow-notification-worker  optional
```

The panel must be reachable by Traefik and by the optional worker on the same Docker network.

### 1. Find your Traefik network

From your existing project, run:

```bash
docker network ls
```

Look for the network used by Traefik. Examples:

```text
myproject_proxy
traefik_proxy
web
edge
```

In the examples below we will call it:

```text
traefik_proxy
```

Replace it with your real network name.

### 2. Create an env file for the panel

Create `.env` next to your compose file:

```env
# Published image
CROWDSEC_PANEL_IMAGE=ghcr.io/gnurub/bastionflow:latest

# CrowdSec LAPI reachable from the panel container
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_USER_AGENT=crowdsec/v1.7.7

# Machine credentials: required for creating/deleting decisions
CROWDSEC_MACHINE_ID=dashboard
CROWDSEC_MACHINE_PASSWORD=replace-me

# Bouncer key: used for reading active decisions
CROWDSEC_BOUNCER_API_KEY=replace-me

# Metrics endpoint, optional but recommended
CROWDSEC_PROMETHEUS_URL=http://crowdsec:6060/metrics

# Public URL used in notification links
CROWDSEC_PANEL_PUBLIC_URL=https://bastionflow.example.com

# SQLite persistence inside the container
CROWDSEC_PANEL_DB_PATH=/data/bastionflow.sqlite

# Internal token for the notification worker
CROWDSEC_INTERNAL_TOKEN=replace-me

# Edge Gate / dashboard password challenge
EDGE_GATE_ENABLED=true
EDGE_GATE_BOT_CHALLENGE_ENABLED=true
EDGE_GATE_AUTH_ENABLED=true
EDGE_GATE_PASSWORD=replace-me
EDGE_GATE_COOKIE_SECRET=replace-me

# Safety defaults for outgoing notification webhooks
CROWDSEC_ALLOW_INSECURE_WEBHOOKS=false
CROWDSEC_ALLOW_PRIVATE_WEBHOOKS=false

# Optional GeoIP fallbacks
CROWDSEC_GEOIP_LOOKUP_URLS=https://ipwho.is/{ip},https://ipapi.co/{ip}/json/,https://free.freeipapi.com/api/json/{ip},https://api.ipwho.org/ip/{ip},http://ip-api.com/json/{ip}
```

### 3. Add the dashboard service to your compose file

Add this service to your existing `docker-compose.yml`:

```yaml
services:
  bastionflow:
    image: ${CROWDSEC_PANEL_IMAGE:-ghcr.io/gnurub/bastionflow:latest}
    container_name: bastionflow
    env_file:
      - .env
    environment:
      CROWDSEC_PANEL_DB_PATH: /data/bastionflow.sqlite
      # This lets the Protection Posture card verify the rendered Traefik file if you mount it.
      # Optional: remove it if you do not mount Traefik dynamic config into the panel.
      CROWDSEC_TRAEFIK_DYNAMIC_CONFIG: /etc/traefik/dynamic/dynamic.yml
    volumes:
      - bastionflow-data:/data
      # Optional, read-only: only needed if you want the posture card to inspect Traefik dynamic config.
      # - traefik-dynamic:/etc/traefik/dynamic:ro
    networks:
      - traefik_proxy
    labels:
      - traefik.enable=true
      - traefik.docker.network=traefik_proxy

      # Main dashboard router. Keep it protected.
      - traefik.http.routers.bastionflow.rule=Host(`bastionflow.example.com`)
      - traefik.http.routers.bastionflow.entrypoints=websecure
      - traefik.http.routers.bastionflow.tls=true
      - traefik.http.routers.bastionflow.priority=10
      - traefik.http.routers.bastionflow.middlewares=bastionflow-chain@docker
      - traefik.http.services.bastionflow.loadbalancer.server.port=3000

      # Public auth/challenge endpoints. These must NOT use edge-gate or you create a redirect loop.
      - traefik.http.routers.bastionflow-public.rule=Host(`bastionflow.example.com`) && (PathPrefix(`/edge-gate`) || PathPrefix(`/api/edge-gate`))
      - traefik.http.routers.bastionflow-public.entrypoints=websecure
      - traefik.http.routers.bastionflow-public.tls=true
      - traefik.http.routers.bastionflow-public.priority=200
      - traefik.http.routers.bastionflow-public.middlewares=bastionflow-public-chain@docker
      - traefik.http.routers.bastionflow-public.service=bastionflow

      # Middleware chain for the dashboard.
      - traefik.http.middlewares.bastionflow-chain.chain.middlewares=bastionflow-headers@docker,bastionflow-ratelimit@docker,crowdsec-bouncer@file,bastionflow-edge-gate@docker

      # Middleware chain for /edge-gate and /api/edge-gate. No edge-gate here.
      - traefik.http.middlewares.bastionflow-public-chain.chain.middlewares=bastionflow-headers@docker,bastionflow-ratelimit@docker,crowdsec-bouncer@file

      # Basic hardening headers.
      - traefik.http.middlewares.bastionflow-headers.headers.browserXssFilter=true
      - traefik.http.middlewares.bastionflow-headers.headers.contentTypeNosniff=true
      - traefik.http.middlewares.bastionflow-headers.headers.frameDeny=true
      - traefik.http.middlewares.bastionflow-headers.headers.referrerPolicy=no-referrer

      # Basic dashboard rate limit.
      - traefik.http.middlewares.bastionflow-ratelimit.ratelimit.average=100
      - traefik.http.middlewares.bastionflow-ratelimit.ratelimit.burst=50
      - traefik.http.middlewares.bastionflow-ratelimit.ratelimit.period=1s

      # Edge Gate forwardAuth handled by the dashboard itself.
      - traefik.http.middlewares.bastionflow-edge-gate.forwardauth.address=http://bastionflow:3000/api/edge-gate/verify
      - traefik.http.middlewares.bastionflow-edge-gate.forwardauth.trustForwardHeader=true

    restart: unless-stopped

volumes:
  bastionflow-data:

networks:
  traefik_proxy:
    external: true
```

Replace:

| Placeholder | Replace with |
| --- | --- |
| `traefik_proxy` | Your real Traefik Docker network |
| `bastionflow.example.com` | Your real dashboard hostname |
| `ghcr.io/gnurub/bastionflow:latest` | Official published image. Pin a version tag for production if preferred. |
| `crowdsec-bouncer@file` | Your real CrowdSec bouncer middleware name/provider |

### 4. If your bouncer middleware is not called `crowdsec-bouncer@file`

Many existing Traefik setups name the bouncer differently. Examples:

```text
crowdsec@file
crowdsec-bouncer@docker
security-crowdsec@file
```

Change this part in the middleware chains:

```yaml
crowdsec-bouncer@file
```

To whatever your stack already uses.

If you do **not** have a CrowdSec Traefik bouncer middleware yet, create one in your Traefik dynamic config. Example file provider config:

```yaml
http:
  middlewares:
    crowdsec-bouncer:
      plugin:
        bouncer:
          enabled: true
          crowdsecMode: live
          crowdsecLapiScheme: http
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiKey: YOUR_BOUNCER_KEY
          crowdsecAppsecEnabled: true
          crowdsecAppsecHost: crowdsec:7422
```

Do not commit `YOUR_BOUNCER_KEY` in a public repository. Render this file from secrets/templates in production.

### 5. Optional: add the notification worker

Add this service if you want Slack/Discord/webhook notifications while the dashboard is closed:

```yaml
services:
  bastionflow-notification-worker:
    image: ${CROWDSEC_PANEL_IMAGE:-ghcr.io/gnurub/bastionflow:latest}
    container_name: bastionflow-notification-worker
    command: ["bun", "scripts/notification-worker.mjs"]
    env_file:
      - .env
    environment:
      CROWDSEC_PANEL_INTERNAL_URL: http://bastionflow:3000
      CROWDSEC_PANEL_DB_PATH: /data/bastionflow.sqlite
    volumes:
      - bastionflow-data:/data
    networks:
      - traefik_proxy
    depends_on:
      - bastionflow
    restart: unless-stopped
```

The worker and dashboard must share the same `/data` volume so they read the same notification routes and dispatch log.

### 6. Start it

```bash
docker compose up -d bastionflow
```

With worker:

```bash
docker compose up -d bastionflow bastionflow-notification-worker
```

Check logs:

```bash
docker logs -f bastionflow
```

Open:

```text
https://bastionflow.example.com
```

### 7. Common integration mistakes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Infinite redirect to `/edge-gate/challenge` | Public `/edge-gate` router also uses Edge Gate middleware | Use a higher-priority router for `/edge-gate` and `/api/edge-gate` without `edge-gate` |
| 404 from Traefik | Wrong Docker network or hostname rule | Set `traefik.docker.network` and verify `Host(...)` |
| Dashboard cannot login to CrowdSec | Wrong machine credentials | Check `CROWDSEC_MACHINE_ID` and `CROWDSEC_MACHINE_PASSWORD` |
| Decisions show empty | Missing/invalid bouncer key | Check `CROWDSEC_BOUNCER_API_KEY` |
| Notifications say worker disabled | Worker not running or cannot reach dashboard | Start worker and set `CROWDSEC_PANEL_INTERNAL_URL=http://bastionflow:3000` |
| Source IPs are wrong | Traefik trusted proxy config wrong | Configure `forwardedHeaders.trustedIPs` for your real proxy chain |


---

## Quick start: local full stack

This is the easiest way to try the project. It starts:

| Service | Purpose |
| --- | --- |
| Traefik | Reverse proxy, access logs, bouncer plugin |
| CrowdSec | Security engine and LAPI |
| Dashboard | This UI |
| whoami | Small protected test service |
| notification-worker | Optional background delivery service |

### 1. Clone the repository

```bash
git clone <your-repo-url> bastionflow
cd bastionflow
```

### 2. Create the local env file

```bash
cp .env.compose.test.example .env.compose.test
```

For a first local run you can keep the defaults. For anything outside localhost, change every value marked as local/change-me.

### 3. Start without notifications

Use this if you only want the dashboard and do **not** need Slack/Discord/webhook background delivery yet.

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml up -d --build
```

Wait a little bit, then check containers:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml ps
```

### 4. Open the dashboard

Open this URL:

```text
http://bastionflow.localhost:8080
```

The dashboard is protected by the Edge Gate password challenge.

Default local password:

```text
local-edge-gate-password-change-me
```

> Important: change `EDGE_GATE_PASSWORD` before using this outside your own machine.

### 5. Open the protected test app

```text
http://whoami.localhost:8080
```

This app is intentionally protected by the same Traefik/CrowdSec/Edge Gate stack, so you can test bans and challenges safely.

---

## Start with notifications enabled

The notification worker is optional. Without it, the UI still works, but notifications will not be delivered in the background while the dashboard is closed.

### 1. Configure your notification target

You can add notification routes from the dashboard UI, or seed them from `.env.compose.test`.

Example Slack seed:

```env
CROWDSEC_NOTIFICATION_CHANNELS=[{"name":"secops-slack","type":"slack","url":"https://hooks.slack.com/services/XXX/YYY/ZZZ","enabled":true,"minSeverity":"high"}]
```

Example Discord seed:

```env
CROWDSEC_NOTIFICATION_CHANNELS=[{"name":"secops-discord","type":"discord","url":"https://discord.com/api/webhooks/XXX/YYY","enabled":true,"minSeverity":"medium"}]
```

Example generic webhook seed:

```env
CROWDSEC_NOTIFICATION_CHANNELS=[{"name":"my-webhook","type":"webhook","url":"https://example.com/crowdsec-events","enabled":true,"minSeverity":"high"}]
```

### 2. Start the stack with the notifications profile

```bash
docker compose --profile notifications --env-file .env.compose.test -f docker-compose.test.yml up -d --build
```

### 3. Confirm the worker is online

```bash
docker logs -f bastionflow-notification-worker
```

In the dashboard, the **Notification routes** card should show:

```text
worker online
```

If it says `worker disabled`, the worker container is not running or the heartbeat cannot reach the dashboard.

### Webhook security defaults

By default, webhooks are hardened:

| Setting | Default | Meaning |
| --- | --- | --- |
| `CROWDSEC_ALLOW_INSECURE_WEBHOOKS` | `false` | Webhooks must use HTTPS |
| `CROWDSEC_ALLOW_PRIVATE_WEBHOOKS` | `false` | Webhooks cannot target localhost/private IPs |

Only enable these in a trusted lab:

```env
CROWDSEC_ALLOW_INSECURE_WEBHOOKS=true
CROWDSEC_ALLOW_PRIVATE_WEBHOOKS=true
```

Do not enable them for Internet-facing deployments unless you really understand the SSRF risk.

---

## Test that everything reacts in real time

### Option A: simple browser test

Open:

```text
http://whoami.localhost:8080
```

Then watch the dashboard. You should see HTTP activity appear in the live feed.

### Option B: simulate attacks

Install project dependencies first:

```bash
corepack enable
bun install --frozen-lockfile
```

Run a local attack simulation:

```bash
bun run simulate:attacks -- --duration=120 --rps=20
```

For visible map arcs in a local lab, use geolocatable demo source IPs. This only spoofs `X-Forwarded-For`; no traffic is sent to those IPs.

```bash
bun run simulate:attacks -- --source-profile=global-demo --duration=120 --rps=20
```

To test dynamic Edge Gate rate limits, hammer `/admin`:

```bash
bun run simulate:attacks -- --install-rate-limit --force-path=/admin --rps=30 --duration=45
```

---

## Common URLs

| URL | What it is |
| --- | --- |
| `http://bastionflow.localhost:8080` | Dashboard |
| `http://whoami.localhost:8080` | Protected test app |
| `http://localhost:8081` | Traefik dashboard, disabled by default |

To enable the Traefik dashboard only for local debugging:

```env
TRAEFIK_API_INSECURE=true
```

Then restart the stack.

---

## Important configuration

Edit `.env.compose.test` for the Docker stack.

### Required secrets to change before non-local use

```env
CROWDSEC_BOUNCER_API_KEY=replace-me
CROWDSEC_DASHBOARD_MACHINE_PASSWORD=replace-me
CROWDSEC_INTERNAL_TOKEN=replace-me
EDGE_GATE_PASSWORD=replace-me
EDGE_GATE_COOKIE_SECRET=replace-me
```

Do not ship the local defaults. They are intentionally obvious.

### Ports

Default HTTP port:

```env
PORT=8080
```

Change it if 8080 is already used:

```env
PORT=8090
```

Then open:

```text
http://bastionflow.localhost:8090
```

### SQLite persistence

The dashboard stores local state in SQLite:

```env
CROWDSEC_PANEL_DB_PATH=/data/bastionflow.sqlite
```

The test compose maps `/data` to the `dashboard-data` Docker volume. This persists:

- notification channels
- notification dispatch history
- local allowlist
- Edge Gate settings
- edge rate-limit rules
- IP enrichment cache

To wipe everything:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml down -v
```

### GeoIP enrichment

The dashboard can enrich public IPs through free providers with fallbacks:

```env
CROWDSEC_GEOIP_LOOKUP_URLS=https://ipwho.is/{ip},https://ipapi.co/{ip}/json/,https://free.freeipapi.com/api/json/{ip},https://api.ipwho.org/ip/{ip},http://ip-api.com/json/{ip}
```

Set it to an empty value if you do not want external lookups.

---

## How Traefik gets the CrowdSec bouncer key

The bouncer key is **not committed** in static Traefik YAML.

Instead:

1. `compose/traefik/dynamic.yml.tpl` contains this placeholder:

   ```yaml
   crowdsecLapiKey: __CROWDSEC_BOUNCER_API_KEY__
   ```

2. The one-shot `traefik-config` service renders it into a Docker volume at startup.
3. Traefik mounts the rendered file read-only from that volume.

This keeps the repository safe for open-source use while still keeping the local compose simple.

---

## Production notes

This project is an operations console. Treat it like infrastructure, not like a public marketing page.

Before production:

- Put it behind VPN, SSO or a trusted reverse proxy.
- Keep Edge Gate auth enabled for exposed routes.
- Change all local secrets.
- Use HTTPS at the outer edge.
- Persist `/data/bastionflow.sqlite`.
- Keep notification webhooks HTTPS-only.
- Do not enable private webhook destinations unless you control the network.
- Review Traefik trusted proxy settings for your real network.
- Use real secret management in your orchestrator when possible.

The Docker image is built as a production Next.js standalone server and runs as a non-root user.

---

## Optional: local HTTPS with Portless

This project includes Portless configuration for a nicer local URL.

Install dependencies:

```bash
corepack enable
bun install --frozen-lockfile
```

Run the Next.js app directly:

```bash
bun run dev
```

Open:

```text
https://bastionflow.localhost
```

Run the full Docker stack through Portless:

```bash
cp .env.compose.test.example .env.compose.test
bun run stack:portless
```

Portless will choose a free port and wire it into the compose stack. On first run it may ask you to trust a local CA. That is expected.

---

## Maintainer guide: build and publish images

The repository includes a Docker Buildx Bake file and GitHub Actions workflows.

### Local image metadata

Print the resolved image build plan:

```bash
bun run image:metadata
```

### Build locally

Build a local AMD64 image and load it into your Docker daemon:

```bash
REGISTRY=ghcr.io IMAGE_NAME=gnurub/bastionflow VERSION=0.1.0 bun run image:build
```

### Push multi-arch image manually

Push `linux/amd64` and `linux/arm64` images:

```bash
REGISTRY=ghcr.io \
IMAGE_NAME=gnurub/bastionflow \
VERSION=0.1.0 \
REVISION=$(git rev-parse HEAD) \
SOURCE=https://github.com/GNURub/bastionflow \
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
bun run image:push
```

### GitHub Actions

Two workflows are included:

| Workflow | File | Purpose |
| --- | --- | --- |
| CI | `.github/workflows/ci.yml` | lint, typecheck, tests and compose config validation |
| Docker image | `.github/workflows/docker-publish.yml` | build multi-arch image and publish to GHCR |

The Docker workflow publishes to:

```text
ghcr.io/<owner>/<repo>
```

Tags generated automatically include:

- branch tags, for example `main`
- pull request tags, build-only, not pushed
- semantic version tags from Git tags like `v1.2.3`
- short SHA tags like `sha-abc1234`
- `latest` on the default branch

To publish a release image:

```bash
git tag v0.1.0
git push origin v0.1.0
```

For the package to be publicly pullable from GHCR, open the GitHub package settings and set package visibility to public.


---

## Stop, restart and clean up

Stop containers but keep data:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml down
```

Restart:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml up -d --build
```

Remove containers and volumes:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml down -v
```

---

## Troubleshooting

### `couldn't find env file: .env.compose.test`

Create it:

```bash
cp .env.compose.test.example .env.compose.test
```

### Dashboard asks for a password

That is expected. Use the value from `.env.compose.test`:

```env
EDGE_GATE_PASSWORD=local-edge-gate-password-change-me
```

### Notification panel says `worker disabled`

Start the stack with the notifications profile:

```bash
docker compose --profile notifications --env-file .env.compose.test -f docker-compose.test.yml up -d --build
```

Then check:

```bash
docker logs bastionflow-notification-worker
```

### CrowdSec container keeps restarting

Check CrowdSec logs:

```bash
docker logs -f bastionflow-crowdsec
```

If you changed collections or AppSec rules, reset the lab volumes:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml down -v
docker compose --env-file .env.compose.test -f docker-compose.test.yml up -d --build
```

### Traefik cannot reach CrowdSec at startup

A short warning during startup can be normal while CrowdSec is still booting. If it continues, check:

```bash
docker logs bastionflow-traefik
docker logs bastionflow-crowdsec
```

### I do not see attacks on the map

Use public/geolocatable source IPs in the simulator:

```bash
bun run simulate:attacks -- --source-profile=global-demo --duration=120 --rps=20
```

Private IPs such as `172.20.0.1` are not geolocatable, so they cannot produce meaningful map arcs.

---

## Development commands

```bash
corepack enable
bun install --frozen-lockfile
bun run lint
bun run typecheck
bun run test
```

Docker compose config validation:

```bash
docker compose --env-file .env.compose.test -f docker-compose.test.yml config
```

---

## License

MIT. See [`LICENSE`](./LICENSE).
