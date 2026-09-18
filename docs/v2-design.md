# honeyLambda v2 design

Status: implementation proposal. No v2 release has been published. This design
starts from `55b4131` (the current v1 default branch).

## What stays

honeyLambda is a small HTTP honeytoken receiver: register a URL, place it where
it should not normally be used, record requests, notify an operator, and return
a chosen decoy response. Keep that scope and the honeyLambda name. A request is
evidence that the URL was fetched, not proof of an intrusion or of who fetched
it. Mail scanners, link previews, proxies and image caches affect interpretation.

## Findings in v1

| Finding | Consequence | v2 change |
| --- | --- | --- |
| Python 2.7, `urllib2`, Python 2 dictionary indexing | Obsolete runtime and incompatible Python 3 code | Replace the small runtime rather than maintain two generations |
| AWS REST API event fields throughout `handler.py` | The README's provider-agnostic claim does not reflect the code | Standard HTTP handler; separate AWS adapter |
| Only the first query parameter is examined | Order-dependent matching; additional parameters can select the wrong response | Match every configured parameter, independently of order |
| Required Host, User-Agent and CloudFront device fields | Ordinary requests can fail with missing headers or an empty device list | Optional, bounded metadata; no inferred device or country |
| Every invocation generates alerts, including unknown tokens | Scanner noise reaches notification providers | Only explicitly configured tokens produce events |
| Cymon lookup and notification calls run inline without timeouts | Unavailable services can prevent the decoy response | Remove Cymon; bound notification time and isolate delivery errors |
| Configuration and response files loaded for every request | Extra I/O and S3 access on the request path | Validate and load once at startup |
| S3 `Get*` / `List*` on `*` in the deployment role | Unnecessary broad permissions | Runtime configuration from a file; no runtime S3 permissions |
| Notification credentials live in JSON | Easy to commit or package secrets | Config names environment variables; credentials injected separately |
| Binary output requires manual API Gateway changes | Fragile deployment; reported setup failures in issue #1 | Raw HTTP bytes and payload-v2 base64 responses |
| No tests, build automation or migration contract | Runtime changes are difficult to assess | Contract tests, CI, migration guide and explicit release gates |

These are source findings, not a diagnosis of issue #1's particular deployment.

## Language decision

| Option | Benefits | Costs | Decision |
| --- | --- | --- | --- |
| Python 3 | Familiar source; capable HTTP and cloud ecosystem | Still needs a rewrite of event handling/config; interpreter and HTTP server packaging | Viable, but little working infrastructure to preserve |
| Go | Standard HTTP server, static binaries, straightforward cross-compilation and concurrency testing | New implementation and AWS adapter to verify | Choose for v2 |
| TypeScript / edge-first | Natural fit for Cloudflare Workers | Provider execution model and another toolchain; less direct binary distribution | Reconsider only if Workers becomes a primary target |

The reason for Go is distribution and maintenance, not an unmeasured performance
claim. Request volume does not require a rewrite for speed. The shared runtime
uses the standard library; only the AWS entry point needs `aws-lambda-go`.

## Deployment decision

Use **Pulumi** for cloud resource lifecycle and keep the Go runtime independent
of deployment tooling. The first draft's CloudFormation plus manual GCP/Azure
recipes left too much setup to the user; that decision is superseded here.

| Option | Fit for this project | Decision |
| --- | --- | --- |
| Separate native templates/CLI recipes | Simple per provider, but separate packaging, registry, IAM, state and teardown workflows | Replace the first draft |
| OpenTofu/Terraform modules | Established resource/state model; still need an image build/push integration and a cross-provider entry point | Reasonable alternative, more glue for this small source-deployed app |
| Serverless Framework | Familiar function-oriented workflow; would need to reconcile Lambda packaging with the two container targets | No advantage over one explicit multi-provider program here |
| Custom Go deployment CLI | Could present one command, but must own state, diffs, dependency ordering, drift and rollback semantics | Do not build a cloud orchestrator |
| Pulumi with TypeScript infrastructure | Providers own lifecycle; one stack interface, normal preview/update/destroy and image-build integration | Choose; accept Node.js as a deployment-only dependency |

The common API is deliberately small: cloud, region, service-config path,
capacity and notification settings; GCP also needs an existing project ID.
Separate stacks select providers. They share the same Go config parser/bundler
and produce the same endpoint and token URL outputs. Provider modules contain
only the differences required by the hosting services.

| Target | Package | Managed infrastructure |
| --- | --- | --- |
| Local / VM | Go executable | Operator's service manager / TLS proxy |
| Generic container host | Non-root OCI image | Existing container platform |
| AWS Lambda | ARM64 `bootstrap`, `provided.al2023` | Function URL, both public invocation permissions, execution role, log group |
| Google Cloud Run | Linux amd64 OCI image | Required APIs, Artifact Registry, dedicated runtime service account, public service |
| Azure Container Apps | Linux amd64 OCI image | Resource group, environment, Log Analytics, ACR, managed identity and pull role, app |

AWS avoids an unnecessary registry and artifact bucket. Container targets use
image digests for updates. Azure uses the deployer's short-lived CLI token for
pushes and a managed identity for pulls; registry admin credentials stay disabled.
The stable Pulumi Docker provider is pinned; its newer Docker Build alternative
is currently documented as public preview. Revisit that provider when stable.

Pulumi state is required; Pulumi Cloud is optional. The framework is absent from
the runtime. Cloud accounts, billing, organization policy, credentials and quota
remain prerequisites. A successful mocked resource test is not a live deployment.
Cloudflare Workers is deferred because it needs a different execution adapter.

Config validation is independent of notification credentials. Packaging snapshots
response assets into content-addressed files and rewrites only the deployed copy;
this prevents relative-path differences across Lambda ZIPs and container images.
Keep one schema and validator instead of a second cloud-specific service schema.
No redaction subsystem, extra threat-intelligence integration, or custom CLI for
cloud orchestration is introduced.

## Runtime contract

1. Load one versioned JSON file at startup; fail on invalid configuration,
   unknown/duplicate/case-misspelled fields, duplicate token selectors or missing
   response assets. Optional remote refresh validates a whole candidate before
   replacing the active snapshot. See [final review](final-review.md).
2. Match the exact escaped path and all configured query parameters. Required
   parameters must occur once with the exact value; extra parameters are allowed.
   A malformed query or a request matching multiple tokens produces no event.
   A path-only token accepts any valid query if it is the only match.
   Do not normalize paths or redirect to canonical paths.
3. For a match, create a timestamped event with a random event ID, stable token
   ID/note, bounded request metadata and source-IP provenance. Unknown URLs get
   the configured default response and produce no honeytoken event.
4. Write each event as one JSON line to stdout, including the full query string.
   Optional body capture has a fixed maximum and records truncation.
5. Attempt optional Slack and JSON webhook notifications within a bounded time
   budget before returning. A sink failure must not alter the decoy response.
   Do not launch background delivery after a serverless handler returns.
6. Use a bounded, per-token, per-process notification cooldown. It suppresses
   outbound attempts only, never event logging. It does not provide distributed
   deduplication and resets on restart or activation of changed config. Multiple instances can notify separately.
7. Return configured bytes/status/content type, with `Cache-Control: no-store`.
   HEAD still triggers a token but sends no response body. This cannot force
   clients or intermediary caches to fetch a URL again.

The direct peer is the default source address. Forwarded headers are accepted
only from explicitly configured proxy CIDRs, walking X-Forwarded-For from right
to left. A malformed chain falls back to the peer. An AWS adapter uses the
gateway's source-IP field and ignores client-supplied forwarding headers. That
field can itself identify a proxy, not an end user. Managed cloud ingress
requires a verified trust configuration; do not guess a globally trusted range.

## Delivery and scope boundaries

Stdout is the event stream, not a built-in durable queue. Configure the hosting
platform's log collection and retention. Webhooks are best-effort, with no
automatic retries or exactly-once guarantee. Redirects are refused. Error logs
must not contain webhook URLs, credentials or response bodies. Slack request
fields are rendered as plain text to avoid attacker-controlled mentions/links.

Keep native Slack notification and a generic JSON webhook. Remove direct SMTP,
Twilio and Cymon integration, remote S3 configuration fetches, device inference,
and obsolete setup screenshots. Email, SMS and reputation enrichment belong in
an operator's downstream workflow. No database, admin API, UI, dynamic token
enrollment API, DNS tokens or fingerprinting engine in this release. Optional
remote JSON snapshots can update the registered token set without redeployment.

If reliable delivery or coordinated throttling is needed, add a durable
queue/outbox adapter in a later PR with retry, idempotency and failure semantics
specified first. Do not label an in-memory queue durable.

## Migration

Keep existing paths, query selectors, notes and response bytes where practical.
The v2 schema deliberately breaks compatibility with v1's configuration. Give
operators a field mapping and a converted example instead of silently accepting
some old fields and discarding others. The old branch/history remains available
for rollback; do not delete an existing cloud stack as part of this refactor.

A new deployment does not preserve the old hostname, API Gateway ID or stage
prefix. Tokens already embedded in documents keep pointing to the old URL.
Keep that endpoint running, or explicitly migrate the owned front door and
verify exact URLs. Test a separate token before moving real traffic. Retaining
the v1 deployment is the safest bridge when its URL cannot be changed.

## PR sequence

1. **Go core and migration:** this design, config/matching/response/event runtime,
   Slack/webhook delivery, CLI, tests and CI; remove legacy code; rewrite README
   and operational/configuration/migration docs.
2. **Cloud deployment:** AWS payload-v2 adapter, non-root container, Go asset bundler,
   unified Pulumi deployments, packaging and resource-contract checks. Stack
   this PR on the core PR so the runtime can be reviewed separately.

## v2 release gates

- [x] Core tests, race detector, formatting and vet pass in CI.
- [x] Binary, HEAD, malformed-query, duplicate-parameter, proxy-spoofing,
      notification-failure and resource-boundary behavior is covered.
- [x] Supported build targets compile; the container builds and serves tokens.
- [ ] AWS, GCP and Azure stacks pass live create/update/rollback/destroy tests.
- [ ] Container ingress source-address behavior is verified on GCP and Azure.
- [ ] At least one real v1 token URL/response is checked against the migration.
- [ ] Event retention, notification failure monitoring and cost settings reviewed.
- [ ] Versioned artifacts, checksums, migration notes and rollback instructions
      are prepared before tagging `v2.0.0`.

## Platform references

Reviewed 2026-09-18:

- [AWS Go runtime and packaging](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html)
- [Function URL payload-v2 request/response contract](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html)
- [Function URL invocation permissions](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Cloud Run container contract](https://cloud.google.com/run/docs/container-contract)
- [Azure Container Apps scaling](https://learn.microsoft.com/en-us/azure/container-apps/scale-app)
- [Cloudflare Workers language runtimes](https://developers.cloudflare.com/workers/languages/)

- [Pulumi state and backends](https://www.pulumi.com/docs/iac/concepts/state-and-backends/)
- [Pulumi Docker resource](https://www.pulumi.com/registry/packages/docker/api-docs/image/)
- [Docker Build provider stability](https://www.pulumi.com/registry/packages/docker-build/api-docs/image/)
- [Azure managed identity image pulls](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity-image-pull)
