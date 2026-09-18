# Remote configuration

Remote configuration lets you add/change/remove tokens and responses without
redeploying the receiver. It is optional: a local, packaged config remains the
bootstrap and fallback for each new process.

The source is a single HTTPS JSON document using the same version-2 schema.
There is no config service to deploy, no background worker, and no new runtime
SDK. Host the document on an endpoint you control. A private endpoint can use a
bearer token. S3, GCS or Azure Blob HTTPS URLs work only when their HTTP access
policy allows the fetch; native cloud IAM signing is **not** implemented.
Presigned URLs also have an expiry and are not a permanent configuration channel.

## Publish a snapshot

Edit and validate your ordinary config, then export it:

```sh
go run ./cmd/honeylambda check -config config.json
go run ./cmd/honeylambda export -config config.json > remote-config.json
```

Upload `remote-config.json` as one object/document through your existing hosting
workflow. Export snapshots local `body_file` assets into `body_base64`, retaining
named response references. A remote document cannot refer to local files or fetch
separate assets. Its maximum size is **4 MiB including encoded bodies**; local
bundles can contain up to 16 MiB of response assets. Export fails before writing
stdout when it cannot produce a valid-size snapshot.

Use an atomic object replacement, keep prior versions for rollback, and configure
the origin/CDN to revalidate the document. ETag support saves unchanged transfers;
a server without ETags can return the document on each refresh. Tokens themselves
are unchanged by export.

## Enable with Pulumi

Keep `configFile` pointing to a local bootstrap snapshot. Configure the channel:

```sh
cd deploy
pulumi config set --secret configURL
pulumi config set --secret configToken  # only for a bearer-authenticated endpoint
pulumi config set configRefreshSeconds 60
pulumi up
```

The secret prompts accept the HTTPS URL and optional bearer token. The same keys
work on AWS, GCP and Azure. `configTimeoutMS` defaults to 2000 (100–5000 allowed).
`configRefreshSeconds` defaults to 60 (5–86400 allowed). Channel settings require
`configURL`; a typo or invalid interval fails before creating cloud resources.

For a standalone binary/container, set these environment variables instead:

| Variable | Meaning |
| --- | --- |
| `HONEY_REMOTE_CONFIG_URL` | HTTPS document URL |
| `HONEY_REMOTE_CONFIG_TOKEN` | Optional bearer token |
| `HONEY_REMOTE_REFRESH_SECONDS` | Refresh interval; default 60 |
| `HONEY_REMOTE_TIMEOUT_MS` | Fetch deadline; default 2000 ms |

Notification credentials remain runtime environment variables. A remote config
can change tokens, responses, metadata and notification policy, but a newly named
notification variable must already exist in the receiver's environment. With
Pulumi, keep destination names enabled in the bootstrap config so deployment
knows which credentials to inject. Changing credential values or the remote
channel itself still requires `pulumi up`.

## Refresh and failure behavior

- The first request in a process attempts a bounded fetch. Later requests perform
  a refresh only when due. There is no polling while idle and no assumption that
  Lambda/Cloud Run continues running background work between requests.
- One request fetches while concurrent requests continue with the current config.
  The fetching request can take up to the configured timeout longer to respond.
- A complete candidate is parsed, validated and initialized before activation.
  Invalid JSON, unknown response references, missing notification credentials,
  oversized bodies, timeouts, redirects and non-200/304 responses keep the current
  config. An invalid snapshot's ETag is not cached.
- Failed refreshes retry on the normal interval. The last valid config has **no
  expiry** within that process; this favors continuing to recognize existing
  tokens during an origin outage. There is no persistent remote cache. A new
  process falls back to its packaged bootstrap if fetching fails.
- Unchanged content/304 responses retain the handler and notification cooldowns.
  A changed config resets per-process cooldowns. Old in-flight requests finish
  with their original snapshot.
- Each instance refreshes independently. Updates are eventually consistent,
  not simultaneous. Removing a token or rolling back is subject to the refresh
  interval and origin/CDN caching. Publish tokens before distributing their URLs.

Events include `config_revision`, a content fingerprint of the active config and
response bytes. It is independent of JSON formatting, key order and asset paths.
`remote_config_applied` and `remote_config_refresh_failed` messages go to stderr;
refresh failures include the revision still active. Monitor them in platform logs.

Pulumi's `tokenURLs` output describes the **packaged bootstrap**. To list URLs for
a newer remote snapshot, use your current authoring config (or downloaded JSON):

```sh
honeylambda urls -config remote-config.json -endpoint https://YOUR_ENDPOINT
```

Rollback means publishing a previous valid document. No infrastructure update is
needed unless you also change the channel or runtime credentials. Keep a recent
bootstrap snapshot in your normal deployment process for cold-start fallback.
