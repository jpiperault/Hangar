# API and MCP server

Hangar can also be driven without the web console: from a script, a CI, or Claude through the MCP server.

## Tokens

Created in **Settings › API tokens** (or **My account** for a "chosen apps" account). A token:

- belongs to an account and never has more rights than it (role, chosen apps);
- has a scope: **read** (state, events, logs, traffic) or **read and deploy** (also: deploy, start, stop, restart);
- never allows deleting an app, changing its settings or reading its secrets;
- is shown only once; Hangar keeps only its SHA-256 hash.

Like the console, the API only answers on the local network. Every action made through the API goes into the
action log (`api:<account>/<token name>`) and the app's events.

## Calls

Header `Authorization: Bearer hgr_…`, JSON responses. Self-signed certificate: `curl -k`, or better the console's
certificate (`/srv/platform/tls/hangar.crt`) with `--cacert`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1` | the token and the list of calls |
| GET | `/api/v1/apps` | visible apps: state, version, machine, address |
| GET | `/api/v1/apps/{slug}` | details, addresses, build (recognised technology, commit) |
| GET | `/api/v1/apps/{slug}/events?limit=30` | latest events |
| GET | `/api/v1/apps/{slug}/logs?period=1h&q=text&errors=1&limit=300` | container logs (`period`: empty, 1h, 24h, 168h) |
| GET | `/api/v1/apps/{slug}/traffic?range=24h` | visitors, pages, errors, referrers, countries, suspects |
| POST | `/api/v1/apps/{slug}/deploy` `{"version": "1.4.0"}` | deployment (empty: the live version; Git repository: rebuilt) |
| POST | `/api/v1/apps/{slug}/start`, `/stop`, `/restart` | start, stop, restart |

A deployment answers `202` at once; its result shows up in the events (health check, then automatic rollback on
failure). `409` if a deployment is already running.

## MCP server (Claude)

`deploy/bin/hangar-mcp`: a single Python 3.9+ file with no dependency, to copy onto the computer running Claude Code
(or to download from the console, next to the tokens). Tools: `list_apps`, `app_status`, `app_logs`, `app_traffic`,
`deploy_app`, `app_action`.

```bash
claude mcp add hangar -e HANGAR_URL=https://192.168.1.10:8443 -e HANGAR_TOKEN=hgr_… \
  -e HANGAR_FINGERPRINT=<fingerprint shown in the console> -- python3 /path/to/hangar-mcp
```

`HANGAR_FINGERPRINT` pins the console's self-signed certificate (connection refused if another machine pretends to
be it). Otherwise `HANGAR_INSECURE=1` accepts any certificate (not recommended). A "read" token is enough to
diagnose; the server asks Claude to confirm with you before deploying or stopping.
