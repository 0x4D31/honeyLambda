# Running honeyLambda

`honeylambda serve` listens on `:8080`, or `:PORT` when the platform sets `PORT`.
Use `-listen 127.0.0.1:8080` for local-only access. Terminate TLS at your ingress
or reverse proxy. Configuration validation happens before opening the listener.
SIGINT/SIGTERM stops accepting new connections and allows up to 15 seconds for
active requests to finish.

## Events and notifications

Collect stdout as newline-delimited JSON and stderr as operational logs. The
service does not retain events on disk. Configure collection and retention on
your platform. A logger outage or a process crash can lose events.

Slack and webhook delivery happens concurrently, under a shared timeout, before
the response completes. Redirects are not followed. Non-2xx responses and
connection errors produce `notification_failed` on stderr with the event ID and
destination type. There are no retries. The handler still returns the decoy
response. Monitor `notification_failed` and `event_write_failed`.

The default 60-second cooldown limits attempts, including failed attempts. It
is per token per process; it resets on restart and is independent across
instances. It never suppresses event logging. Set it to 0 if every request
should attempt a notification. For durable retries or distributed deduplication,
consume the event stream with your existing pipeline.

## Client addresses

By default `source_ip` is the direct TCP peer. An arbitrary X-Forwarded-For
header cannot override it. If you own a reverse proxy, configure only its actual
CIDRs in `trusted_proxies` and make sure clients cannot bypass it using those
addresses. The receiver walks X-Forwarded-For from right to left through trusted
proxies; a malformed chain falls back to the peer. Other forwarding headers
are ignored. `/0` is rejected.

Behind managed cloud ingress, the default may identify an ingress proxy.
Do not guess its address range. Verify the platform's forwarding behavior and
network boundary before trusting that range. In the AWS adapter, the gateway's
source-IP field takes precedence and client-supplied forwarding headers are
ignored. A proxy or email scanner can still be the observed client.

## Deployment checks

Use a TCP health probe. There is no public HTTP health endpoint, so probes do
not need a honeytoken URL. Check a dedicated token after deployment and confirm
its response bytes and event. Testing a notification invokes the configured
destination; use a separate test destination when appropriate.

For public deployments, choose a maximum instance count/concurrency and log
retention suitable for the expected traffic. Unknown requests still consume
hosting resources even though they produce no honeytoken events. These settings
do not impose a hard spending cap.
