# Private session engine

This opt-in overlay applies to upstream v3.9.1, commit
`16536500b6b96840675e08aded74af14c22619a8`. `build-engine.py` exports that exact
Git revision, copies the authored Go files, applies checked patch anchors, runs
the overlay unit tests and builds a scratch image. The upstream checkout is
not modified. The Go builder is pinned by digest. `TRIPWIRE_SHELL=1` activates
the new SSH handler; other protocol handlers keep their upstream behavior.

Each SSH channel owns its virtual filesystem, current directory and model
history. Reconnects and simultaneous channels start fresh, even with the same
username and source IP. No virtual file survives disconnection. The prompt
follows the current directory. Virtual commands never use host file APIs or
execute processes. The provider can answer read-only system commands (`ps`,
`uptime`, `df`, `free`, `netstat`, `ss`, and nonstatic `uname`/`nproc`) but cannot
change virtual state. Configured static identity answers take priority.

Supported commands: `pwd`, `cd`, `ls` (including `-l`, `-a`, `-A`), `cat`,
`echo`, basic `printf`, `touch`, `mkdir`/`mkdir -p`, `rm`, file-only `cp`/`mv`,
`whoami`, `id`, `hostname`, `true`, `false`. Quoting, selected variables,
`;`, `&&`, `||`, and output redirection are supported. This is a bounded shell
subset: no pipelines, command substitution, globbing, scripts, symlinks,
permissions model, general environment assignments or complete Bash expansion.
Unsupported syntax is rejected; unknown executables return command-not-found.
Network tools return a simulated timeout and never perform network IO.

Limits: 256 filesystem entries, 16 KiB per virtual file, 256 KiB total file
content, 16 KiB command input, 8 KiB output, and at most seven complete history
pairs / 16 KiB history. History trimming preserves pairs and releases old
backing arrays. These limits are per session; the existing container memory
limit remains the outer bound. The upstream IP-based model rate limiter still
applies across sessions; it is deliberately separate from history isolation.

Provider calls inherit SSH cancellation and have a 32-second client deadline.
Failures return `bash: temporarily unavailable; try again` (inline exit status
75), preserve virtual state and are excluded from history. No automatic retry
adds provider spending. Engine events identify model failures in `Handler`;
the current Vector schema stores their command/output but not that extra field.
Raw model and request content is omitted from plugin debug diagnostics.

Build and test from the repository root:

```sh
python3 beelzebub/build-engine.py
TRIPWIRE_TEST_IMAGE=localhost/tripwire-beelzebub:session-v1 python3 beelzebub/test-local.py
python3 beelzebub/test-vector.py
```

The real SSH test covers simultaneous same-IP sessions, fresh reconnects,
dynamic prompts, a 100-command history, provider errors, recovery and a stalled
provider deadline, plus existing authentication/forwarding/transfer checks.

For an authorized private deployment, save the tested image to an ignored
`*.local.tar` archive, obtain its immutable `sha256:` image ID with Podman,
and run `deploy-session-engine.py --host ALIAS --archive PATH --image ID`.
It loads the image under the existing engine account, adds `compose.session.yaml`
to the existing private deployment, and recreates only that engine. It backs up
the previous configuration locally on the host and restores it if the live
synthetic smoke test fails. No sentinel, gateway, firewall or sshd changes.
Host keys still change when the engine is recreated. Verify exact synthetic
session command/output pairs in OpenSearch before treating rollout as complete.
