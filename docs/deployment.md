# Deployment

Use the Pulumi project in `deploy/` for AWS, GCP, or Azure. It owns the receiver,
permissions, logs, and (where needed) registry and container environment. There
is one `pulumi preview` / `pulumi up` / `pulumi destroy` workflow. No artifact
bucket, prebuilt image, registry login script, or custom deployment CLI is needed.

These definitions have automated resource-contract and packaging tests. **Live
creation, update, and teardown on all three clouds remain v2 release gates.**
Do not interpret mocked provider tests as a successful cloud deployment.

## First deployment

Install Go 1.26+, Node.js 22+, and the [Pulumi CLI](https://www.pulumi.com/docs/install/).
GCP and Azure also require Docker with BuildKit; AWS builds a native Lambda ZIP
and does not require Docker. Build Lambda from Linux/macOS or WSL to preserve
executable permissions. Azure requires the Azure CLI for registry authentication.

From the checkout root, create your service configuration as described in the
[README](../README.md#create-a-token). To try the public test tokens first:

```sh
cp examples/config.json config.json
go run ./cmd/honeylambda check -config config.json
cd deploy
npm ci
pulumi login
pulumi stack init aws-dev
pulumi config set cloud aws
pulumi config set region us-east-1
pulumi up
pulumi stack output endpoint
pulumi stack output tokenURLs --json
```

Authenticate to the selected cloud before `pulumi up` (see below). Pulumi's
normal preview and confirmation remain available. Preview validates and bundles
the service config; AWS also compiles Go. Container builds/pushes occur on update.
Token URLs preserve configured escaped paths and encode the query parameters.

`pulumi login` uses Pulumi Cloud for state by default. You can instead use a
[DIY backend](https://www.pulumi.com/docs/iac/concepts/state-and-backends/), including
`pulumi login --local` for evaluation. Preserve your state and secrets-provider
credentials; choose a shared backend for team use. Pulumi is a deployment-time
dependency and does not run in the receiver.

## Select a cloud

Create a **separate stack per cloud/environment**. Keep its cloud and region
stable; changing either in an existing stack can replace resources and URLs.
The service JSON remains the same.

| Setting | AWS | GCP | Azure |
| --- | --- | --- | --- |
| `cloud` | `aws` | `gcp` | `azure` |
| Example `region` | `us-east-1` | `us-central1` | `eastus` |
| Additional setting | None | `projectId` | None |
| Runtime | Lambda, ARM64, Function URL | Cloud Run, Linux amd64 | Container Apps, Linux amd64 |
| Registry | Not needed | Created Artifact Registry | Created Basic ACR |
| Runtime identity | Logs in its own log group | Dedicated service account, no project roles | User-assigned identity, registry pull only |
| Logs | CloudWatch, 14 days | Cloud Logging, project's retention policy | Log Analytics workspace, 30 days |

For another cloud, repeat stack initialization and settings, then use the same
`pulumi up` command. For example:

```sh
pulumi stack init gcp-dev
pulumi config set cloud gcp
pulumi config set region us-central1
pulumi config set projectId YOUR_EXISTING_PROJECT
pulumi up
```

### Cloud authentication and account prerequisites

- **AWS:** use standard AWS credentials, an instance/CI role, or an authenticated
  AWS profile (`AWS_PROFILE`). The deployer needs Lambda, IAM role/policy,
  CloudWatch Logs and Function URL permission-management access. If you set
  `maxInstances`, reserved concurrency must fit the account quota,
  including its unreserved capacity. AWS defaults to unreserved concurrency so
  new accounts with low quotas can deploy.
- **GCP:** use Application Default Credentials (`gcloud auth application-default
  login`) or an equivalent CI identity. Select an existing billing-enabled
  project. The deployer must be able to enable APIs, manage Artifact Registry,
  create/act as the runtime service account, manage Cloud Run, and grant public
  invocation. The stack enables Run, Artifact Registry and IAM APIs; it leaves
  these project-wide APIs enabled on destroy. Organization policy must permit
  `allUsers` invocation for a public honeytoken endpoint.
- **Azure:** use `az login` and `az account set --subscription SUBSCRIPTION_ID`.
  Use the same subscription/identity for Pulumi and the Azure CLI. The deployer
  must be able to create resource groups, Container Apps, Log Analytics, ACR,
  managed identities and the registry-scoped `AcrPull` role assignment. This
  requires role-assignment permission as well as resource creation. Azure CLI
  obtains a short-lived ACR push token automatically. ACR admin access stays
  disabled; the running app pulls through its managed identity.

Cloud billing, account permissions, organization policies, region availability
and quotas cannot be provisioned away by the application. No cloud credentials
are stored in the service configuration.

## Deployment settings

All application deployment keys use the `honeylambda` Pulumi namespace.
Provider authentication follows the providers' normal mechanisms.

| Key | Meaning / default |
| --- | --- |
| `cloud` | Required: `aws`, `gcp`, or `azure` |
| `region` | Required cloud region identifier |
| `projectId` | Required for GCP; existing project |
| `configFile` | Service JSON path, relative to `deploy/`; default `../config.json` |
| `maxInstances` | Optional integer 1–100; Lambda reserved concurrency (default unreserved) or container maximum replicas (default 2) |
| `slackWebhook` | Pulumi secret, required only when service config enables Slack |
| `webhookURL` | Pulumi secret, required only when service config enables the JSON webhook |
| `configURL` | Optional secret HTTPS remote-config URL |
| `configToken` | Optional secret bearer token for `configURL` |
| `configRefreshSeconds` | Remote refresh interval, 5–86400; default 60 |
| `configTimeoutMS` | Remote fetch deadline, 100–5000; default 2000 |

For notifications, enable the destination in your service JSON, then enter its
URL at the secret prompt:

```sh
pulumi config set --secret slackWebhook
pulumi config set --secret webhookURL
pulumi up
```

Set only the destinations you enable. The deployment maps each value into the
environment-variable name in `alerts`, so you do not maintain separate names
per cloud. Azure uses Container Apps secret references; Lambda and Cloud Run use
runtime environment settings. The values remain secrets in Pulumi state. Azure receives a template revision
fingerprint so changing only a secret value also rolls out a new app revision. Anyone
with permission to inspect the corresponding cloud runtime configuration may
also have access to them.

Response assets resolve relative to the source JSON, including files outside
its directory. The Go bundler snapshots them into content-addressed files and
rewrites the packaged config automatically. Duplicate bodies share one file.
The original JSON is unchanged. No runtime S3 reads or cloud-specific config
formats are involved.

## Updates, rollback, and removal

Edit the Go source, service config, or response files and run `pulumi up` again.
The Lambda archive and container build context include the packaged config.
With [remote config](remote-configuration.md), ordinary token/response updates
only require publishing a new JSON snapshot. Pulumi token URL outputs describe
the packaged bootstrap; use `honeylambda urls` for the latest remote snapshot.
Cloud Run and Container Apps receive an **image digest**, so a changed build
updates the service even though the registry staging tag is reused.

To roll back, restore the prior source and service config, then run `pulumi up`
and inspect the preview. Provider-managed resource names stay stable for normal
updates. Replacement, recreation, or a new stack can change the endpoint; see
[migration](migration.md) before changing already distributed token URLs.

```sh
pulumi preview
pulumi up
pulumi destroy
```

Destroy removes the resources this stack owns, including its registry and logs.
It leaves the GCP project and enabled APIs intact. Export logs before removal if
you need them later. Registry images are retained until explicitly removed or the stack is destroyed,
so automatic age/tag cleanup cannot break a running or rollback revision. Registry
storage and log ingestion can incur charges even when the app scales to zero. Maximum instance settings are capacity controls,
not spending limits. Cloud Run can briefly exceed revision instance limits.

Containers scale to zero, accept concurrent requests, and use TCP startup probes;
there is no public health URL that could collide with a token. AWS uses a
20-second timeout and 128 MiB (including remote refresh and notification time); Cloud Run uses its second-generation environment,
1 CPU/512 MiB and a 30-second request timeout; Azure uses 0.25 CPU/0.5 GiB.

## Local and other container hosts

No Pulumi or Node.js is needed to run the Go binary or build the Dockerfile.
To package an arbitrary config and its response files yourself:

```sh
go run ./cmd/honeylambda bundle -config config.json -out build-config
docker build --build-arg CONFIG_DIR=build-config -t honeylambda:local .
```

The bundle output directory must not already exist. Keep it inside the Docker
build context. A default build uses the self-contained examples:

```sh
docker build -t honeylambda:example .
docker run --rm -p 127.0.0.1:8080:8080 honeylambda:example
```

The non-root image reads `/config/config.json`, listens on `PORT` (default 8080),
and includes CA certificates for outbound HTTPS. You can mount a prepared config
directory at `/config` instead; it must be readable by UID 65532.

## Live verification before v2

For each cloud, test create, no-change update, source/config/asset update, rollback,
and destroy in an isolated stack. Request a dedicated token and verify response
bytes, HEAD behavior, the event and a real notification. Confirm provider IAM
propagation, image pulling, cold starts and account quotas in that account.

AWS events use the Function URL's source-IP field. With default container
configuration, events may identify the ingress proxy. Verify the actual ingress
chain before setting `trusted_proxies`; do not guess CIDRs. Platform request logs
can provide additional client metadata. This source-address limitation remains
part of the Cloud Run/Azure release validation, not something unit tests establish.

## References

- [Pulumi state and backends](https://www.pulumi.com/docs/iac/concepts/state-and-backends/)
- [Pulumi Docker image updates and digests](https://www.pulumi.com/registry/packages/docker/api-docs/image/)
- [AWS Function URL permissions](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Cloud Run container contract](https://docs.cloud.google.com/run/docs/container-contract)
- [Cloud Run memory requirements](https://docs.cloud.google.com/run/docs/configuring/services/memory-limits)
- [Azure managed identity image pulls](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity-image-pull)
