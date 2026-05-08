# Security design

This panel is intentionally private-network first. The browser talks only to Next.js API routes; those routes talk to CrowdSec LAPI, Prometheus, and optional `cscli`.

## Controls

- Credentials live only in server environment variables.
- Write operations require machine credentials and are never sent to the browser.
- Automatic decisions go through allowlist, duration, evidence, and rate-limit checks.
- Auditable security events are appended as JSON lines to `/tmp/bastionflow-audit.log` by default.
- `cscli` is executed without shell interpolation and only for fixed inventory commands.

## Deployment assumption

Run behind a private network, VPN, or authenticated reverse proxy. The MVP intentionally does not include app-level login because access is controlled outside the app.
