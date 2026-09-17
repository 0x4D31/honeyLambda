# Migrating from v1

v2 replaces the Python 2 handler and Serverless Framework configuration. It is
not an in-place stack update. Keep the old deployment running while testing v2.
The original implementation remains in Git history at `55b4131`.

## Configuration mapping

| v1 | v2 |
| --- | --- |
| `traps[path]["key=value"]` | A `tokens` entry with `path`, `query: {"key":"value"}` and a unique `id` |
| `note` | `tokens[].note` |
| `default-http-response` | `default_response` |
| `http-response` | `tokens[].response` |
| `content-type` | `content_type` |
| `body` (a file path) | `body_file` (relative to the new config file) |
| `alert.slack.webhook-url` | Environment variable named by `alerts.slack_url_env` |
| `alert.email` / `alert.sms` | Removed; route JSON webhook/events to email or SMS automation |
| `threat-intel-lookup` / Cymon | Removed; optional enrichment downstream |
| `configFile`, `s3Bucket`, `s3Key` | Removed; mount/package a config file and set `HONEY_CONFIG` |
| `serverless.yml` | Removed; deploy the binary/container or use the AWS example in the cloud PR |

Old config files are rejected, not partially interpreted. Download an existing
S3 config outside the application if needed, and check each token and asset.
No runtime S3 access is required.

## Equivalent v1 example

The example below preserves the two original URL selectors and response types.
Place it at the checkout root as `config.json`. Unlike v1, query order is
irrelevant. A request containing both selectors is ambiguous and gets no event.

```json
{
  "version": 2,
  "default_response": {
    "status": 200,
    "content_type": "text/html",
    "body_file": "assets/old-default.html"
  },
  "tokens": [
    {
      "id": "secret-document",
      "path": "/v1/get-pass",
      "query": {"user": "jack"},
      "note": "token is embedded in secret.doc",
      "response": {
        "status": 200,
        "content_type": "image/png",
        "body_file": "static/pixel.png"
      }
    },
    {
      "id": "login-breadcrumb",
      "path": "/v1/get-pass",
      "query": {"page": "2"},
      "note": "hidden link in login page"
    }
  ]
}
```

Copy your existing default response to `assets/old-default.html` before running
`honeylambda check -config config.json`. Do not change an HTML response into an
empty/default response unless you intend that behavior change.

## Preserve the public URL

The hostname and stage prefix are part of every token already placed. Moving
from API Gateway to a new Function URL, Cloud Run service or Azure app creates a
different address. The application cannot redirect requests that never reach
it. For an existing AWS `.../dev/v1/get-pass?user=jack` URL:

- Keep the old API endpoint serving old tokens while placing new v2 URLs; or
- Migrate an owned custom domain/front door deliberately and verify its path
  mapping, including `/dev` if the proxy forwards it; or
- Adapt the existing API Gateway integration separately. The first v2 AWS
  adapter accepts payload-v2 events, not v1 REST API proxy events.

When a proxy preserves `/dev` in the path, configure `/dev/v1/get-pass` in v2.
When it strips that prefix, configure `/v1/get-pass`. Test the **exact URL already
embedded**, not merely a new endpoint with a similar suffix.

## Behavioral changes

Unknown or ambiguous URLs no longer trigger alerts. Required query parameters
must occur once; extra parameters are allowed. Missing User-Agent/CloudFront
headers do not fail requests. No device/country inference or reputation lookup
is performed. Notifications default to a 60-second per-process cooldown and a
2-second deadline. Configuration updates require restart/redeploy.

Validate a small token set and its response bytes/events first. Configure any
email/SMS replacement before removing those v1 notifications. Roll back by
restoring traffic to the old deployment and configuration. Do not delete its
stack until old URLs have been accounted for.
