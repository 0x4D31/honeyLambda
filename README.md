# honeyλ

Small HTTP honeytokens. Put a decoy URL in a document, inbox, configuration file
or browser history. When that URL is requested, honeyLambda records an event,
optionally sends an alert, and returns a response you control.

**v2 is under development.** This branch replaces the original Python 2 / AWS
implementation with Go. Read the [migration guide](docs/migration.md) before
changing an existing deployment.

- Exact path and query matching, with a stable ID and note for each token.
- Custom status, content type, text or binary response, including a 1×1 pixel.
- JSON events on stdout, Slack notifications and a generic JSON webhook.
- One HTTP server for local use, VMs and container platforms.
- No Serverless Framework, database or threat-intelligence service required.

A hit means the URL was fetched. Link scanners, preview bots and email image
proxies can trigger tokens too; it does not establish who opened a document or
prove malicious intent.

## Try it locally

Install a supported Go release (1.26 or newer), then from this checkout:

```sh
go build -trimpath -o bin/honeylambda ./cmd/honeylambda
./bin/honeylambda check -config examples/config.json
./bin/honeylambda serve -config examples/config.json -listen 127.0.0.1:8080
```

In another terminal:

```sh
curl -i 'http://127.0.0.1:8080/v1/get-pass?user=jack'
```

You should receive a PNG and see a JSON event for `secret-document` on stdout.
The example sends no external notifications. Unknown URLs return the default
404 response and produce no honeytoken event.

## Create a token

Generate a random value, then add it to your configuration:

```sh
./bin/honeylambda token
```

```json
{
  "version": 2,
  "default_response": {"status": 404, "body": "Not found\n"},
  "tokens": [{
    "id": "finance-document",
    "path": "/export/REPLACE_WITH_RANDOM_VALUE",
    "note": "URL placed in the finance decoy document",
    "response": {"status": 200, "body": "Export expired\n"}
  }]
}
```

Save this as `config.json`, run `honeylambda check`, and restart the service with
it. The `token` command generates 128 random bits; it does not register or deploy
a token. Use unique, unpredictable values for real tokens. The public examples
are only for testing.

## Notifications

Add environment-variable **names** to `alerts` in your configuration:

```json
"alerts": {
  "slack_url_env": "HONEY_SLACK_URL",
  "webhook_url_env": "HONEY_WEBHOOK_URL",
  "timeout_ms": 2000,
  "cooldown_seconds": 60
}
```

Set the named variables in your runtime. You can configure either destination or
both; URLs must use HTTPS. The generic webhook receives the same JSON event as
stdout. Route it to your existing automation for email, SMS or enrichment.

Notifications are best-effort and finish before the HTTP response. A failed
notification leaves the decoy response unchanged. The cooldown limits attempts
per token **per process**; every matched request is still recorded. Configure
log collection and retention on your hosting platform.

## Documentation

- [Configuration and event format](docs/configuration.md)
- [Operating the receiver](docs/operations.md)
- [Migrating from v1](docs/migration.md)
- [v2 design, tradeoffs and release gates](docs/v2-design.md)

Cloud packaging and provider-specific deployment instructions are the next PR
in the v2 series; this core branch is directly runnable as an HTTP service.

## Development

```sh
go test -race ./...
go vet ./...
```

The core uses the Go standard library. Tests exercise matching, binary/HEAD
responses, source-address trust, request capture limits, notification failures
and concurrent requests. No live cloud account or notification credentials are
needed for these tests.

## License

GPL-3.0-or-later, preserving the original project's license. See [LICENSE](LICENSE).
