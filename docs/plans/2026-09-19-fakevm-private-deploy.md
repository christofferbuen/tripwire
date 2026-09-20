# Private fake-SSH deployment

Status: corrected collector batch approved and deployed successfully.
The operator selected private SSH-to-OpenSearch verification before public
exposure. Broad hardening remains deferred. No public bait activation here.

First approved collector attempt applied cluster objects but rolled code
back when an overly strict verifier rejected OpenSearch's equivalent mapping
serialization. Read-only inspection confirmed an empty fakevm write index,
correct fields, permissions, retention and enabled bait monitor. The verifier
now normalizes string false and omitted default index:true only. A disposable
Podman OpenSearch/Vector test passed with all 41 synthetic engine events.
The corrected deployment bundle requires a new recorded checksum before retry.

The approved retry completed: deployed-file and bundle checksums passed,
live alias/mapping/template/role/retention/primary checks passed, and the
bait-used monitor is enabled. The enricher restarted successfully and its
loaded code includes fakevm indices. The private bootstrap log confirms the
ntfy test was delivered and a dashboard import was reported. The fakevm index
contains zero events; the private engine/session step remains outstanding.
No sentinel or administrative SSH changes were made by this collector batch.

## Collector batch

`beelzebub/build-collector-bundle.py` packages exactly five changed collector
files, the installer, verifier and checksum manifest. Files are normalized
to LF. The bundle is ignored local output and carries no secrets or host facts.

`beelzebub/send-collector-bundle.py` verifies the approved archive hash and
member whitelist, then streams bytes over SSH. It creates a private staging
directory under the stack owner's home and runs `deploy-collector.sh` there.
Binary transport avoids PowerShell's added CRLF. The SSH alias is supplied
by the operator outside this document.

The installer checks every deployed baseline hash before changing files,
syntax-checks bootstrap, checks the enricher is available, and backs up the
five original files into a unique private directory. The reviewed deployed
enricher differs from HEAD only in two old geography test fixtures; the
bundle builder requires its observed checksum explicitly.

It replaces those five files in place, runs bootstrap to install mappings,
retention, writer permissions, dashboards and monitors, and invokes the
existing ntfy notification test. This notification is part of the requested
batch approval. Existing credentials remain on the host. Bootstrap output
is retained in the private backup directory, not printed into the chat.

The verifier checks the live write alias, closed mapping, field types,
template parity, role, policy, primary availability and enabled bait monitor.
Then only the enricher is restarted, and its running state is checked.
The receiver, collector Vector and OpenSearch are not restarted.

On failure after installation starts, the installer restores the five code
files and restarts the enricher. Additive cluster changes may remain. This is
code rollback, not a cluster snapshot or a promise to undo mappings. Never
delete existing indices to roll back. A disconnected or interrupted SSH
session requires inspecting the live state before retrying the batch.

## Private engine and shipping batch (completed)

The operator authorized completing the deployment and live command test
without further routine approval pauses. The engine runs under a separate
account, binds only loopback and uses an internal Podman network. Its user
service is enabled, log rotation is configured, and the shipper has read
access to the log directory through a named-user ACL. The engine account
cannot read the sentinel shipper secret. The initial static-command stage
used no model credentials. The operator subsequently approved model activation
and sending commands/history externally. The bounded gateway and internal relay
are now running, and a model-backed session's start, command/output and end
were verified in OpenSearch. The provider key is isolated from the engine;
its $5 cap was verified. Gateway restart and post-restart relay authentication
passed. Public exposure and full-host reboot testing remain outstanding.

Only Vector was recreated. The original sentinel container ID was unchanged
and fresh sentinel events were verified afterward. A rootless-network cleanup
warning occurred during the recreation, but the replacement Vector remained
running, passed both sink health checks and delivered the new session.

Live OpenSearch verification passed for one interactive session with exactly
five events: start, whoami/deploy, pwd/home directory, id/expected UID-GID, end.
The first read preceded batch/refresh visibility; the subsequent exact-session
query and strict verifier both passed. No real visitor payloads were read.
User-service enablement is verified; a host reboot was not performed.

The procedure used was:

Prepare a separate fake-VM Unix account, private configuration, shared log
permissions and a loopback-only listener on an unused high port. Keep the
existing sentinel listener and its identity volume. Before model-enabled
operation, resolve independent HTTP timeouts and log bounds; a static-command
smoke test can establish session ingestion without a paid model request.

Install the additional Vector config and log mount only after the collector
verification passes. Validate with the actual existing secret backend before
recreating only Vector. Capture a baseline timestamp for sentinel ingestion.
Use an SSH tunnel for one private login and static command, then verify start,
command/output and end events by session ID in OpenSearch. Inspect synthetic
test content only, and verify sentinel ingestion continues after recreation.
No claim of production client-IP preservation follows from a tunneled test.

## Public launch remains separate

The private engine now runs the tested session overlay on pinned upstream
v3.9.1. Its immutable loaded image ID is
`sha256:b60369cc6306e0ca51d40a46c03360adda42e5fdbe612b9dc8d7c7a368797be9`.
Session-owned bounded virtual files, working directory and history replace
shared IP/user context; the prompt follows `cd`. Provider failures produce a
temporary error, stay out of history and preserve virtual state. Client calls
inherit SSH cancellation and a 32-second deadline. The gateway's tighter
bounds remain active.

Local real-SSH tests passed concurrent same-IP/user isolation, clean reconnects,
a 100-command session, bounded history, failed-provider recovery and a stalled
provider deadline, plus the prior authentication/forwarding/transfer checks.
The live rollout verified two simultaneous sessions and one fresh reconnect,
then checked all 35 events / 29 command-output pairs in OpenSearch. Initial
smoke verification exposed asynchronous upstream log ordering; configuration
rollback worked, and the verifier now compares exact pair multiplicities.
No model/session payload was exported from private deployment diagnostics.

Post-rollout checks confirmed the original sentinel container identity, running
gateway/relay/Vector, loopback-only SSH, internal engine network, read-only root,
valid admin SSH configuration and the existing provider cap. Supported shell
syntax and remaining limitations are documented in `beelzebub/engine/README.md`.

Follow-up private evaluation: the gateway now disables provider reasoning,
accepts intentionally silent stopped responses, rejects token truncation,
escapes terminal control characters and trims complete history pairs. Removed
the static `pwd` answer so directory changes are visible to the model. Nine
live state commands passed; all eleven events and exact outputs were checked
in OpenSearch. The five-command semantic regression also passed. Gateway,
relay, engine, sentinel and Vector remained running; administrative SSH
configuration validation passed. The listener remains loopback-only and the
engine root filesystem read-only. OpenSearch retained its existing yellow
status with seventeen unassigned replicas. No reboot or public exposure test
was performed in this follow-up. Prompt updates and a deterministic virtual
filesystem remain future work; sampled model correctness does not prove them.

Review and verify narrowly scoped outbound containment, independent request
and log bounds, provider spending limit, source-IP preservation, restart
ordering and log access. Only afterward enable the public fake SSH port and
HTTP bait. Administrative SSH configuration remains outside this deployment.
