# Deployment

The HTTP binary and the AWS adapter share the same receiver and configuration.
These recipes are provided for v2 development. Local tests/builds do not establish
that a recipe has been deployed successfully in a real cloud account.

| Target | Delivery | Live cloud verification |
| --- | --- | --- |
| Local / VM | `go build`, HTTP server | Not applicable; local smoke test |
| Container host | Dockerfile, Linux amd64/arm64 | Check on your target host |
| AWS Lambda | ARM64 ZIP and CloudFormation | Required before release |
| Google Cloud Run | Linux amd64 container | Required before claiming verified support |
| Azure Container Apps | Linux amd64 container | Required before claiming verified support |

## Container

Build with the self-contained example configuration:

```sh
docker build -t honeylambda:v2-dev .
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:8080:8080 honeylambda:v2-dev
curl -i 'http://127.0.0.1:8080/v1/get-pass?user=jack'
```

The image runs as UID/GID 65532, includes CA certificates for HTTPS webhooks,
and writes no application data to disk. It listens on `PORT` (default 8080).

For your own tokens, create a directory containing `config.json` and any assets
referenced relative to it. Use `body_base64` for a self-contained binary response,
or keep response assets within that directory. Then either bake that directory
into your deployment image:

```sh
docker build --build-arg CONFIG_DIR=deploy-config -t honeylambda:my-config .
```

Or mount it at `/config` at runtime:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --mount type=bind,src="$(pwd)/deploy-config",dst=/config,readonly \
  honeylambda:v2-dev
```

The directory must be readable by UID 65532; for baked configuration, the Docker
copy sets ownership. Keep URLs for configured notification destinations in
runtime environment variables. There is no public HTTP health path; use a TCP
probe against the listening port.

To build a multi-architecture image with an existing registry:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg CONFIG_DIR=deploy-config \
  -t REGISTRY/honeylambda:VERSION --push .
```

Use an immutable tag or digest for deployments. Do not deploy the public example
tokens as your real token set.

## AWS Lambda

Prerequisites: Go, `make`, `zip`, AWS CLI, and an artifact bucket in the target
region. This recipe creates a **new public endpoint**. Read the
[migration guide](migration.md) if existing tokens use an API Gateway URL.

```sh
go run ./cmd/honeylambda check -config deploy-config/config.json
make lambda CONFIG_DIR=deploy-config
aws s3 cp dist/honeylambda-lambda-arm64.zip \
  s3://YOUR_ARTIFACT_BUCKET/honeylambda/UNIQUE_BUILD_ID.zip
aws cloudformation deploy \
  --template-file deploy/aws/template.yaml \
  --stack-name honeylambda-v2 \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    CodeBucket=YOUR_ARTIFACT_BUCKET \
    CodeKey=honeylambda/UNIQUE_BUILD_ID.zip
aws cloudformation describe-stacks --stack-name honeylambda-v2 \
  --query 'Stacks[0].Outputs' --output table
```

For an isolated smoke deployment, `make lambda` defaults to `examples/`. The
ZIP contains `bootstrap` and `config/`. Response assets must stay within that
config directory; the service starts from `config/config.json`.

The template uses `provided.al2023`, ARM64, 128 MiB, a 10-second function timeout,
reserved concurrency 2 and 14-day log retention. Its execution role can write
only to its own log group. It does not fetch configuration from S3 at runtime.
Choose a different `FunctionName` if deploying multiple stacks. Concurrency
reservation requires available account quota.

Both `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` permissions are
included for public Function URLs; direct invocation is constrained to requests
through the URL. `AuthType: NONE` is intentional: decoy links must be fetchable.

If notifications are configured, supply the optional `SlackWebhookURL` and/or
`WebhookURL` parameters through your deployment process (Secrets Manager dynamic
references can be used). Their values populate `HONEY_SLACK_URL` and
`HONEY_WEBHOOK_URL`. A named but unset notification variable fails startup.

Use a new S3 object key for every update; overwriting the same key does not
ensure CloudFormation updates the function. Preserve an old ZIP/key to roll
back. The adapter accepts Function URL and HTTP API **payload-v2** events,
preserves raw query parameters and binary bodies, and uses the gateway's source
IP. It does not accept REST API payload-v1 events. No API Gateway binary-media
console configuration is needed for Function URLs.

## Google Cloud Run

Push a configured image to an existing Artifact Registry repository that the
service can pull from. Cloud Run requires Linux amd64 (include it in a
multi-architecture image).

```sh
gcloud run deploy honeylambda \
  --image REGION-docker.pkg.dev/PROJECT/REPOSITORY/honeylambda:VERSION \
  --region REGION \
  --port 8080 \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 2 \
  --concurrency 20 \
  --timeout 30
```

Cloud Run sets `PORT` and terminates TLS. Use a dedicated service account with
only the permissions your deployment needs. If using notification destinations,
inject their named environment variables using Cloud Run's secret references
and grant the service account access to those particular secrets. Configuration
and relative assets come from the image above; changing them means redeploying.

Verify source-address handling before relying on it: by default events record
the TCP peer, which may be a Google ingress proxy. No provider CIDRs are guessed
by the application. See [proxy configuration](operations.md#client-addresses).

## Azure Container Apps

Use an existing Container Apps environment and a configured Linux amd64 image
the environment can pull. Set up registry authentication first when needed.

```sh
az containerapp create \
  --name honeylambda \
  --resource-group RESOURCE_GROUP \
  --environment CONTAINER_APPS_ENVIRONMENT \
  --image REGISTRY/honeylambda:VERSION \
  --ingress external \
  --target-port 8080 \
  --transport http \
  --min-replicas 0 \
  --max-replicas 2 \
  --cpu 0.25 \
  --memory 0.5Gi
```

Inject notification destinations through Container Apps secret references using
the variable names in your config. Use TCP health probes on port 8080. Confirm
the ingress forwarding behavior before configuring trusted proxy ranges; the
default source address can be an ingress proxy. Neither this command nor the
Cloud Run recipe proves the original user's IP behind an additional proxy.

Maximum instances/concurrency reduce capacity but are not hard spending caps.
Check the platform logs and a dedicated token after each deployment.

## References

- [AWS Go packaging](https://docs.aws.amazon.com/lambda/latest/dg/golang-package.html)
- [Function URL event/response format](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html)
- [Function URL permissions](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Cloud Run container contract](https://cloud.google.com/run/docs/container-contract)
- [Azure Container Apps ingress](https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview)
