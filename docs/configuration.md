# Configuration

Load a version-2 JSON file with `-config` or `HONEY_CONFIG` (default:
`config.json`). Local configuration and response assets are read at startup; restart or redeploy
to apply changes. Optional [remote refresh](remote-configuration.md) can update
the active snapshot while running. Unknown fields, duplicate JSON keys, incorrect
field casing, null values and invalid UTF-8 are rejected. Optional fields should
be omitted when unused.

JSON is the single service format. Add `"$schema": "./config.schema.json"` in a
root-level config for editor completion/validation with the supplied schema.
The Go loader is authoritative for references, paths, byte limits and asset files.
No schema is downloaded by the runtime.

## Fields

| Field | Meaning / default |
| --- | --- |
| `version` | Required, `2` |
| `tokens` | Required, 1–10,000 token definitions |
| `responses` | Optional named response definitions; at most 1,000 |
| `default_response` | Response for unknown URLs and tokens without an override; defaults to 200, empty text |
| `alerts.slack_url_env` | Optional environment variable containing a Slack incoming-webhook URL |
| `alerts.webhook_url_env` | Optional environment variable containing a JSON webhook URL |
| `alerts.timeout_ms` | Notification budget, 1–5,000 ms; omitted/0 means 2,000 |
| `alerts.cooldown_seconds` | Per-token, per-process interval between notification attempts; default 60; 0 disables |
| `capture_body_bytes` | Body prefix to include in events; default 0; maximum 65,536 |
| `trusted_proxies` | CIDRs allowed to supply X-Forwarded-For; default empty |

Setting an alert variable name but leaving that environment variable empty is
a startup error. Each destination must be an HTTPS URL without userinfo or fragment.
`check` validates configuration and response assets without resolving credentials;
`serve` validates credentials before opening the listener. Destination variable
names must be distinct and cannot overwrite process/cloud settings such as
`PORT`, `HONEY_CONFIG`, `HONEY_REMOTE_*`, `HONEY_DEPLOYMENT_REVISION`, `AWS_*` or `K_*`.

## Tokens and matching

```json
{
  "id": "document-42",
  "path": "/api/export",
  "query": {"key": "RANDOM_VALUE", "format": "csv"},
  "note": "Placed in the decoy export instructions",
  "response": {"status": 200, "content_type": "text/csv", "body": "name,email\n"}
}
```

- IDs are unique, 1–128 characters: letters, digits, `.`, `_`, `-`; the first
  character must be a letter or digit. A note is optional, up to 1,024 bytes.
- Paths are exact **escaped** paths, start with `/`, and contain no query or
  fragment. `/a`, `/%61`, `/a/` and `/A` are distinct. No path cleaning occurs.
- Every configured query key must appear exactly once and match its decoded
  value. Parameter order does not matter. Extra parameters are allowed.
- Omitting `query` creates a path-only token. A malformed query matches nothing.
- If a request matches multiple token definitions, it produces **no event** and
  receives the default response. Identical selectors fail configuration loading.
  This avoids choosing a token based on configuration order.
- All methods reaching the handler can trigger a token, including HEAD and
  OPTIONS. The hosting gateway can impose its own method restrictions.
- Request targets over 8 KiB do not match. Configured paths are limited to 2 KiB.

For example, the two v1-style selectors in `examples/config.json` work separately.
`?user=jack&page=2` matches both and deliberately produces no event.

## Responses

`status` defaults to 200; `content_type` defaults to `text/plain; charset=utf-8`.
Use one of `body`, `body_base64` or `body_file`. With none specified the body is
empty. An override replaces the entire default response, rather than merging it.

```json
{
  "status": 200,
  "content_type": "image/png",
  "body_file": "assets/pixel.png"
}
```

Relative files resolve from the **configuration file's directory**. Files must
be regular files and are read once, up to 1 MiB each. Combined response bodies
are limited to 16 MiB. Text and base64 bodies use the same limits. Statuses
204/205/304 require an empty body. No request values are substituted into responses.

Responses include `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
HEAD sends the same status/headers as GET, without response bytes. You do not
need a different configuration for a binary response on an HTTP server.

## Reusable responses

Define a response once and refer to it from any number of tokens:

```json
{
  "version": 2,
  "responses": {
    "expired-export": {
      "status": 200,
      "content_type": "text/plain; charset=utf-8",
      "body": "This export has expired.\n"
    }
  },
  "tokens": [
    {"id": "document-a", "path": "/export/RANDOM_A", "response_ref": "expired-export"},
    {"id": "document-b", "path": "/export/RANDOM_B", "response_ref": "expired-export"}
  ]
}
```

Use either `response` for an inline override or `response_ref` for a named response.
Missing references and using both fields are errors. Named response IDs use the
same character rules as token IDs. Named bodies count once toward the aggregate
response-size limit; references share the loaded bytes. Inline overrides and the
existing `default_response` behavior are unchanged.

## Portable configuration bundles

`honeylambda bundle -config PATH -out NEW_DIRECTORY` validates the config and
copies its loaded response bodies into a portable directory. It rewrites body
references in the output `config.json`, preserves exact bytes, deduplicates bodies,
and leaves the source config unchanged. The output directory must not exist.
Neither `check`, `bundle` nor `export` sends alerts or requires notification
credentials. `export` writes self-contained JSON to stdout for remote hosting;
`urls -endpoint URL` prints the configured token URLs without registering them.

Pulumi and `make lambda` use this same bundler. Cloud, region, capacity and
notification values belong to the [deployment settings](deployment.md#deployment-settings),
not this JSON. A config/asset change takes effect after redeployment or restart.

## Event format

Each matched request writes one JSON object plus a newline to stdout.
`config_revision` identifies the config and response bytes used for that request;
it is an additive field in event schema version 1. The
generic webhook gets the same object. Operational errors go to stderr.

```json
{
  "schema_version": 1,
  "id": "64f687c934d1d28108fddac80c738c6d8",
  "time": "2026-09-17T12:00:00Z",
  "token_id": "secret-document",
  "note": "URL embedded in secret.doc",
  "request": {
    "method": "GET",
    "path": "/v1/get-pass",
    "query": "user=jack",
    "host": "example.com",
    "peer_ip": "192.0.2.10",
    "source_ip": "192.0.2.10",
    "source_ip_from": "peer",
    "user_agent": "curl/8"
  },
  "notification_suppressed": false
}
```

`source_ip_from` is `peer`, `trusted_proxy`, `gateway`, or an `_unavailable`
variant when no valid peer/gateway address is available. `peer_ip` is the
immediate connection peer (or the gateway's asserted peer in an adapter).
See [operations](operations.md) for proxy behavior.

The full query string is retained. Host (256 bytes), User-Agent (512 bytes),
Content-Type (256 bytes) and method (32 bytes) are bounded. If body capture is
enabled, `body_base64` contains the byte prefix; `body_truncated` marks a prefix
shorter than the received body, and `body_read_error` marks an incomplete read.
The event schema version is independent of the application/configuration major
version.
