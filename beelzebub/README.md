# Fake SSH: local preparation

Private deployment is running on the sentinel under a separate Unix account,
with loopback-only SSH and an internal container network. Collector integration
is deployed. A real interactive SSH test was verified in live OpenSearch:
start, whoami, pwd, id and end, with the expected outputs and one session ID.
The existing sentinel container was preserved and continued shipping events.
Startup is enabled, but reboot recovery has not been tested. Model-backed
commands now work through the private relay and fixed-origin gateway after
explicit operator approval to send SSH commands/history to OpenRouter. A
synthetic model-backed session and its exact returned output were verified
in live OpenSearch. Public bait remains disabled. No firewall, sshd or WireGuard
changes were made. The provider development key was previously used
only through a hidden in-memory prompt for one compatibility request; it
is not in these files. All repeatable engine tests use a dummy key.

## Checks

The latest live evaluation passed nine directory-state/silent commands and
verified all eleven session events, including exact command/output pairs, in
OpenSearch. `pwd` now uses model history instead of a fixed home-directory
answer. A second live test passed unknown-command, echo, printf and listing
checks. These are sampled model behaviors, not a deterministic filesystem.
The visible prompt remains fixed, and upstream history still shares context
across reconnects with the same client IP and username.

The gateway explicitly disables reasoning while retaining its 512-token cap;
silent stopped completions are accepted, while token-truncated replies fail.
[OpenRouter documents the shared reasoning/output budget](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens).
Local Podman tests cover silent null replies, history-pair trimming, escaped
terminal control characters, auth, response limits, deadlines and overload.
Gateway diagnostics contain status/error types only, never session content.
Run `test-gateway.py` in a Linux helper; the smoke client's `--state` and
`--semantics` modes use the approved private deployment and paid model.
The default smoke test also now needs the model for `pwd`.

From the repository root (Python standard library and Podman):

```sh
python3 beelzebub/render.py --selftest
python3 beelzebub/test-local.py
python3 beelzebub/test-vector.py
python3 beelzebub/test-bait.py
python3 beelzebub/test-integration.py
python3 beelzebub/test-compose.py
python3 beelzebub/test-opensearch.py
python3 sentinel.py --selftest
python3 enrich.py --selftest
python3 droppers.py --selftest
python3 dashboards.py --selftest
bash -n bootstrap-opensearch.sh
```

`test-local.sh` wraps the Python harness. Image pulls and the Alpine test
client build need network access; subsequent SSH/stub tests run on an
internal network with no published ports. Test containers, volumes and the
network are removed on exit. The helper image remains cached. Synthetic
logs remain under ignored `capture.local.logs/` for the real-log Vector tests.
Never point these tests at production logs.

The local engine tests passed: anchored-password refusals, matching sentinel
banner, static and model-backed commands, interactive events, no actual
command execution, forwarding and transfer rejection, burst limit, session
deadline, dummy authorization and exact custom prompt. The ten Vector tests
passed against the actual captured log shape and the existing sentinel
config. HTTP bait tests and the existing sentinel wire goldens passed.
Mapping/consumer checks exercise the actual template generator and verify
template/live field parity; these are not live OpenSearch deployment tests.
The Linux Podman run also passed the live TCP_INFO assertion, HTTP bait,
wire goldens, enrichment and dropper selftests, and Bash syntax validation.
Compose validation confirms the real document defaults to loopback-only SSH.

The disposable Podman OpenSearch 3.8.0 integration test also passed: all 41
synthetic engine events reached the write alias through the actual Vector
transform, including correlated interactive starts/commands/ends and stored
command output. It reproduced OpenSearch's mapping normalization (string
`"false"` and omitted default `index: true`) and verifies that meaningful
mapping differences still fail. This unpublished internal-network test uses
disabled authentication and a no-op GeoIP pipeline fixture; it does not prove
production credentials, GeoIP enrichment or alert delivery.

## Verified upstream reference

- Source tag v3.9.1: commit `16536500b6b96840675e08aded74af14c22619a8`.
- Upstream publication workflow: `.github/workflows/deploy.yml` in that tag,
  publishing `docker.io/m4r10/beelzebub:v3.9.1`.
- Registry index digest, resolved with `podman image inspect` and checked
  with `podman manifest inspect`:
  `sha256:f8e6acbc67a3838a9aa52c0473ac20e04aed8be02e1f131d6188acc0b6ff17f7`.
- Tested linux/amd64 manifest:
  `sha256:03c16c5b44d8528b09fbcbc0cf583875bd07b85900473edf79e594977e00f373`.
- Source and registry provenance were checked; no independent signature
  attestation or reproducible-build proof is claimed.
- Relevant source: `internal/protocols/strategies/SSH/ssh.go`,
  `internal/plugins/llm-integration.go`, `internal/plugins/llm_adapter.go`,
  `internal/builder/director.go` and `internal/tracer/tracer.go`.

One direct OpenRouter compatibility request on 2026-09-19 using
`deepseek/deepseek-v4-flash` returned nonempty terminal text, using 170 input
and 29 completion tokens; provider-reported cost was USD 0.000020748.
The request used the upstream message structure with an additional 512-token
test cap. This verifies provider compatibility, not a full engine-to-provider
or VM containment test. `live-check.py` can repeat it, prompting for a key
without echo; it never saves the key or accepts it as an argument.

`deploy-private.sh` records the authorized private deployment operation;
it is not an idempotent general installer. `smoke-private.py` runs the static
SSH test with an on-host askpass helper that is removed afterward, keeping
the generated password out of argv and output. `verify-session.py` reads only
the selected synthetic session and validates all five events. Allow Vector's
batch interval and OpenSearch's refresh interval before checking results.

## Private model gateway

The gateway removes upstream's fabricated `pwd` / `/home/user` seed exchange
and reinforces literal Bash command semantics. This corrects an observed
model reply that returned a directory for `hello`. Live SSH retests passed
for two unknown commands, echo, printf and ls; all seven session events and
the corrected responses were verified in OpenSearch. Empty model output is
accepted for commands that legitimately print nothing. This is still model
simulation, not a real shell or a guarantee of consistent filesystem state.

`gateway.py` runs under a separate host account and holds the real provider
key in a mode-600 host secrets file inaccessible to the engine account. The
engine and `gateway-relay.py` containers share an internal network; the relay
has no published port and reaches only the gateway Unix socket. The engine
holds a separate local authentication token. The provider key is absent from
both container environments. The OpenRouter key's $5 cap was verified live.

The gateway fixes the model and HTTPS origin, refuses redirects, strips extra
request fields, caps requests at 64 KiB, provider responses at 128 KiB,
completion tokens at 512, retained context at 16 messages/32 KiB and active
requests at two. A parent process kills workers after a 30-second total
lifetime, including stalled headers and trickled responses. `test-gateway.py`
passed inside a network-disabled Podman container against a loopback stub,
covering authentication, caps, redirects, provider failures, deadlines,
overload and worker cleanup. No real keys or paid calls are used by that test.

The gateway restart test passed with the mounted socket directory preserved,
and unauthenticated relay requests still receive 401 after restart. Only the
dedicated engine user's manager is ordered after the gateway at startup.
Full-host reboot testing, public client-IP preservation and broader outbound
containment remain outstanding. The gateway enforces its fixed origin in
application code; it is not a host-wide firewall or protection after compromise
of the gateway account. Upstream history allocation/context sharing remains
unchanged. Daily log rotation is not an instantaneous disk-size ceiling.

## Render and later deployment

The fake-VM user renders on the VM:

```sh
python3 beelzebub/render.py --env beelzebub/.env --out beelzebub/runtime.local.config
```

Required env values: `BAIT_PASSWORD`, `SERVER_NAME`, `FAKEVM_PORT` for
Compose, and `OPEN_AI_SECRET_KEY` for model calls. Optional values:
`LLM_MODEL` (DeepSeek V4 Flash), `LLM_ENDPOINT` (OpenRouter chat completions),
`DEADLINE` (600 seconds), `RATE_REQUESTS` (10), `RATE_WINDOW` (60 seconds),
and `FAKEVM_BIND` (loopback). No live values or bait-file template belongs
in this repository. Rendered service config contains the bait password,
so keep its directory private. The renderer writes UTF-8 with LF and mode
600 files on Unix. It refuses unrelated files in the services directory.

Compose is preparation-only: do not expose it until the narrow containment
plan is reviewed and its VM tests pass. Use a separate Unix user, protect
the env file with mode 600, create `/var/log/tripwire-fakevm` with ownership
and traversal permissions permitting the fake service to write and Vector
to read, and verify those permissions. No metrics port is published;
upstream Prometheus is explicitly bound to container loopback.

Collector bootstrap and its local scripts must land before the new Vector
config ships data. The sentinel Compose file now requires the extra config
file and log-directory mount. Rebuild the sentinel only when enabling its
new HTTP feature. Enabling `--bait-env` and mounting the operator-written
bait file is a later explicit deployment edit; its default stays off.

## Deviations and remaining limits

- The approved amendment allows local preparation before containment and
  separates HTTP bait from STARTTLS. The SMTP/TLS refactor was not done.
- The renderer encodes substitutions as JSON/YAML scalars, instead of raw
  substitution into quoted YAML. This keeps Python regex escapes valid in
  YAML and Go. The SSH version omits the prefix added by gliderlabs/ssh.
- HTTP bait is disabled on HTTPS as well as Apache, preserving the approved
  HTTP-only scope. Token detection covers HTTP requests/bodies/Basic auth
  and currently decoded SMTP usernames; TLS password capture is deferred.
- The OpenAI-compatible caller refuses an empty key without making a
  request. Tests use an explicitly fake nonempty key, then verify no request
  when it is removed.
- Upstream accepts the correct password for any username. The static
  answers describe deploy, so another username can expose that inconsistency.
  An unmodified upstream image cannot enforce a deploy-only username here.
- Real logs use top-level `event`. `SourcePort` is a string. Login attempts
  have passwords/client banners and independent IDs; session starts do not
  carry those fields. Interactive end events omit IP and username. Vector
  preserves these ends by session ID, without fabricating an IP; invalid IPs
  on other events are dropped. Do not claim password-to-session correlation.
- Inline SSH commands log as Start, not Interaction. Digest counts reflect
  those upstream labels. The address panel compares bait fetch/login counts;
  it does not establish a temporal join or compute time since bait delivery.
- gliderlabs adds the SSH prefix. The runtime test confirms the final banner
  matches the sentinel. The Go key-exchange stack differs from OpenSSH.
- Host keys change on container recreation. No persistence hook was found
  in the reviewed SSH strategy; the image is unmodified.
- Rate limiting is a replenishing token bucket, not a fixed minute window.
  The eleventh immediate request is refused. Static answers cost no model
  call. Rate-limit errors appear as `command not found` in this release.
- Model history is keyed by client IP plus username, not the logged session
  UUID. Reconnecting with the same pair reuses history; two clients behind
  one address using the same username can share context. The history cleaner
  removes entries after 60 minutes of inactivity, with a one-minute sweep.
  There is no message-count or byte cap in the reviewed history store.
  OpenSearch session IDs remain separate; model context isolation does not.
- The provider request has no output-token limit. The rate-limiter map also
  has no eviction in the reviewed implementation. Container memory limits
  bound the process, but exhaustion can restart it and lose model history.
  These limits must not be described as per-session budget enforcement.
- Only `exit` closes an interactive session; `logout` is a static response.
- The session deadline closes SSH, but the source uses background contexts
  and a Resty client with no explicit request timeout. It does not prove
  cancellation of an in-flight model request. Resolve this before exposure
  (for example a separately reviewed bounded outbound proxy).
- Podman creates mount-point directories in the writable layer even for
  a read-only scratch image. Tests compare before/after diffs and check the
  marker's absence in tmpfs, rather than requiring an initially empty diff.
- T8 verifies source IP on the local internal bridge, not the VM's public
  rootless port-forwarding path. That path remains a mandatory deployment
  test; no automatic host-network fallback was enabled.
- Runtime ports are private/loopback in preparation. Local tests do not
  establish production UID-based filtering, reboot persistence, log access,
  alert delivery, API spending enforcement or protection after host-root
  compromise. Those are deployment gates, not passed tests.
- Raw engine logs precede Vector truncation and have no built-in rotation
  in the reviewed configuration. The deployment runbook must bound/rotate
  them; OpenSearch retention does not remove the VM's raw files.
