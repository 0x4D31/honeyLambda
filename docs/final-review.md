# Final v2 review

Review base: `f9f5498`, 2026-09-18. The existing PRs remain drafts.

## Decisions

- Keep Pulumi, isolated in `deploy/`. The engine/CLI are Apache-2.0, the 3.x
  line has existed since 2021, and current releases remain active. Self-managed
  backends avoid a mandatory hosted-service dependency. This is evidence of
  maturity, not a guarantee about future maintenance. Pin dependencies, retain
  state backups and keep normal cloud resources and standalone runtime packages.
- Keep JSON as the single canonical service format. A YAML syntax layer would
  add parser/coercion/alias behavior without fixing the actual schema problems.
  Add an editor schema and reusable named responses instead. Keep existing valid
  v2 JSON working; reject ambiguous or misspelled input that was silently accepted.
- Remote configuration is an optional HTTPS document source, separate from
  service settings. Use the same parser and validation, with no separate cloud
  service schema and no per-request object-store SDK calls. Inline response bytes
  make a remote document one atomic snapshot. Native IAM-backed object-store
  readers and a token-management API are outside this implementation.

## Implemented changes and acceptance checks

1. Strict configuration: reject duplicate/case-misspelled keys, null values,
   conflicting response body fields and invalid UTF-8. Add named responses,
   reject missing references and conflicting environment names. Cover invalid
   inputs and config/bundle/export round trips with regression tests.
2. Remote configuration: start from a validated local snapshot; fetch HTTPS on
   the first request and periodically when requests arrive. Bound fetch time/size, use
   ETags, retain the last valid handler on failure, and serialize refresh without
   blocking concurrent requests behind a fetch. No background task that depends
   on serverless CPU between requests. Add a self-contained export command.
3. Runtime: preserve monotonic time for notification cooldowns, serialize events
   across config generations, isolate notification completion from client
   disconnects, and report active configuration revisions in events.
4. Deployment: wire remote settings consistently; make notification rotation
   trigger an Azure revision; scope Azure CLI authentication to the provider's
   subscription; retain images for rollback; make
   builds reproducible and verify the generated container context in CI.
5. Authoring: add `init` with exclusive file creation and a fresh random token,
   and `urls` to list URLs for local or published configurations.
6. Docs/tests: explain lifecycle, stale config behavior, limits and rollback;
   provide a JSON Schema and examples; run Go/race/vet, packaging, infrastructure
   tests and CI. Record live-cloud requirements separately from mocked tests.

## Evidence and remaining release gates

- [Pulumi engine and license](https://github.com/pulumi/pulumi)
- [Pulumi 3.0 announcement](https://www.pulumi.com/blog/pulumi-3-0/)
- [Current releases](https://github.com/pulumi/pulumi/releases)
- [State backends](https://www.pulumi.com/docs/iac/concepts/state-and-backends/)

Live cloud creation, updates (including notification rotation), rollback,
image pulling, quota/IAM propagation and teardown still require real accounts.
Container ingress client-IP attribution remains unverified; do not infer a
trusted proxy CIDR from unit tests. Remote HTTP retrieval does not implement
S3/GCS/Azure IAM authentication; a private endpoint can use a bearer token.

## Pulumi dependency and exit path

Current evidence: Pulumi 3.263.0 was released on 2026-09-16, following 3.262.0 on
September 10 and 3.261.0 on September 2. The open-source 3.x line dates to 2021.
The receiver has no Pulumi API dependency; cloud resources continue running
without the Pulumi CLI/service. Export and back up state (`pulumi stack export`)
and retain the chosen secrets-provider credentials. A hosted-backend change can
use Pulumi's documented backend migration. A framework change would still require
importing existing resource IDs and reviewing lifecycle differences; it is not
an automatic conversion, but the Go runtime and service config remain portable.

Provider corrections follow the documented lifecycle behavior:
- [Azure secret changes do not create a revision](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets)
- [Artifact Registry cleanup policies](https://docs.cloud.google.com/artifact-registry/docs/repositories/cleanup-policy)

Automatic registry cleanup is removed: tag/age policies cannot determine whether
a digest is still in use by a serving or rollback revision. Azure deployment embeds an environment fingerprint in
the container template so credential-only changes create a revision. Runtime
images use digests; Go builds disable embedded VCS state for reproducibility.

Local validation covers Go race tests/vet, CLI initialization and URL rendering,
strict parsing, named-response bundle/export round trips, real HTTPS refresh and
redirect handling, last-valid fallback, refresh concurrency, event revisions,
all three mocked provider graphs, Azure secret rotation, JSON Schema validation
and repeatable Lambda builds. CI additionally builds and smoke-tests the actual
container context generated by the deployment packager. Live cloud checks above
are still required; they have not been replaced by unit tests.
