# OpenSearch: off the demo security configuration

2026-09-20. Deployed on the collector the same day: `--check` passed all
twelve lines, the demo users and their role mappings are gone, and the node
serves and trusts only certificates made on that host. Kept as the record of
what was wrong and how the fix was tested.

## Problem

`compose.yaml` ran OpenSearch 3.8.0 with `DISABLE_INSTALL_DEMO_CONFIG:
"false"`. Verified on the collector:

1. Six demo users keep their default passwords (`readall`, `kibanaserver`,
   `logstash`, `kibanaro`, `snapshotrestore`, `anomalyadmin`). `readall` reads
   every index. They are `reserved`, so `admin` cannot change them over REST.
2. `opensearch.yml` trusts `CN=kirk,OU=client,O=client,L=test,C=de` as
   `admin_dn`, and `kirk.pem` / `kirk-key.pem` are the static pair shipped in
   the image (issued 2024-02-20). The key is public: a TLS client presenting
   it on 9200 is super-admin.
3. Node and HTTP certificates are the same demo set.

Port 9200 is published on the WireGuard address, reachable from the sentinel
VM, which is the host expected to be compromised.

## Target state

- Own CA, own node certificate, own admin client certificate, generated on
  the host that runs the cluster, never committed, never leaving that host.
- `opensearch.yml` supplied by us (bind mount), `admin_dn` = own admin cert,
  `DISABLE_INSTALL_DEMO_CONFIG: "true"`, no `kirk*.pem` / `esnode*.pem` in use.
- Internal users: `admin`, `kibanaserver` (own password), plus whatever
  `bootstrap-opensearch.sh` creates (`sentinel-writer`). No other demo user.
- Dashboards logs in with `kibanaserver` and the new password from `.env`.
- Every existing client keeps working unchanged: they all skip certificate
  verification today (`curl -k`, `enrich.py` `INSECURE`, Vector
  `verify_certificate = false`, Dashboards `VERIFICATIONMODE none`). Making
  them verify against the new CA is a follow-up, not this package.
- Existing data, users created over REST, roles, ISM policies, monitors and
  saved objects survive: the security index and everything else live in the
  `opensearch-data` volume, which is not touched.

## Package (one builder, model: opus; the risk is lockout and rootless file ownership)

Fence: `compose.yaml` (services `opensearch` and `dashboards` only), new
`harden-opensearch.sh`, new `test-opensearch-hardening.sh`,
`setup-logging.sh` (only to add the new `.env` key), `.gitignore` (one line).
Nothing else. No commits, no git state changes. Never read `.env`,
`*.local.*` other than this plan and the findings file, `*-secrets.json`.
No SSH, no remote host: everything is built and tested with local podman.

### `harden-opensearch.sh` (bash, same flag style as `harden-sentinel.sh`)

- `--render`: idempotent; creates `./opensearch-config/` (mode 700) holding
  - `root-ca.pem`, `node.pem`, `node-key.pem`, `admin.pem`, `admin-key.pem`
    (keys PKCS#8, mode 600). Generate with `openssl` if the host has it,
    otherwise in a throwaway container with the keys written straight to the
    bind mount. Subjects are dull and carry no hostname of the operator:
    `CN=opensearch-node,O=tripwire` and `CN=opensearch-admin,O=tripwire`.
    Node cert SAN: `DNS:opensearch`, `DNS:localhost`, `IP:127.0.0.1`.
    Existing files are never overwritten (a second `--render` is a no-op);
    `--render --rotate` is NOT in scope.
  - `opensearch.yml`: the settings the demo installer would have written,
    with our file names, `plugins.security.authcz.admin_dn` and
    `plugins.security.nodes_dn` set to the two subjects above,
    `plugins.security.allow_default_init_securityindex: true`,
    `plugins.security.ssl.http.clientauth_mode: OPTIONAL`, audit and
    `restapi.roles_enabled` as the demo has them, and the non-security lines
    compose already passes by environment left to the environment.
  - `internal_users.yml`: only `admin` and `kibanaserver`, hashes produced by
    the image's own `plugins/opensearch-security/tools/hash.sh` run in a
    throwaway container, passwords read from `.env`
    (`OPENSEARCH_INITIAL_ADMIN_PASSWORD`, new `DASHBOARDS_SERVICE_PASSWORD`)
    on a file descriptor or stdin, never argv. This file matters only for a
    fresh data volume; an existing security index ignores it.
- `--apply-users`: for an existing cluster. Using the own admin certificate
  from inside the OpenSearch container, over REST: set `kibanaserver`'s
  password to `DASHBOARDS_SERVICE_PASSWORD`, delete the other five demo users
  and `admin`-unrelated demo role mappings that name them. Must not touch any
  user it does not name. Idempotent (404 on delete is success).
- `--check`: read-only, exit 0 only if all hold; prints one line per check:
  1. each of the six demo names with its default password gets 401
     (`kibanaserver:kibanaserver` included), `admin:admin` gets 401;
  2. `admin` with the `.env` password gets 200;
  3. the certificate served on 9200 is not issued by `Example Com Inc.`;
  4. the running container's `opensearch.yml` has no `kirk` in `admin_dn`;
  5. Dashboards `/api/status` answers 200 with the `.env` admin login
     (proves the `kibanaserver` service login works).
  Takes `--url` and `--dash-url` so the test harness can point it at a
  throwaway cluster; defaults as in `bootstrap-opensearch.sh`.
- `--selftest`: what can be checked with no cluster (argument parsing,
  rendered `opensearch.yml` contains no `kirk`, no demo file name, refuses to
  overwrite existing keys).

### `compose.yaml`

- `opensearch`: `DISABLE_INSTALL_DEMO_CONFIG: "true"`; read-only bind mounts
  of `./opensearch-config/opensearch.yml`, the five PEM files and
  `internal_users.yml` to their places under `/usr/share/opensearch/config/`.
  Rootless podman on SELinux (Rocky): pick the mount options (`:Z`, `:U`, or
  ownership set by `--render` with `podman unshare chown 1000:1000`) that let
  uid 1000 in the container read mode-600 keys, and say in a comment why.
  Do not change ports, memory, healthcheck, image or volumes. The comment on
  line 171 ("Performance analyzer...") sits above the wrong key today; fix it
  while there.
- `dashboards`: `OPENSEARCH_USERNAME: kibanaserver`, `OPENSEARCH_PASSWORD:
  ${DASHBOARDS_SERVICE_PASSWORD:?set this in .env}`.
- `setup-logging.sh`: generate `DASHBOARDS_SERVICE_PASSWORD` the same way it
  generates the admin password, only when the key is missing.
- `.gitignore`: `opensearch-config/`.

### Acceptance tests: `test-opensearch-hardening.sh` (planner-authored; implement exactly these)

One entrypoint, local podman, own compose project name, loopback ports other
than 9200/5601, own throwaway volumes, a generated throwaway `.env` in a temp
directory, hard timeout per stage, everything torn down on exit (trap), exit
code honest.

- **T1 fresh install.** `--render`, `up` opensearch + dashboards, wait
  healthy, `--check` passes, `bootstrap-opensearch.sh` runs to the end
  against it (it may need its URL variables pointed at the test ports; do not
  edit the script, use the environment it already reads; if it cannot be
  pointed, report that instead of editing it).
- **T2 migration, the case that matters.** Start the stack from the
  *unmodified* `compose.yaml` of `git show HEAD:compose.yaml` (demo config)
  on a fresh volume; create user `sentinel-writer` with a known password and
  index one document. Stop. Switch to the new compose + `--render`. Start.
  Assert: `admin` still logs in, the document is still there,
  `sentinel-writer` still authenticates, demo users STILL work at this point
  (expected: the security index survived). Run `--apply-users`. `--check`
  passes. `sentinel-writer` still authenticates.
- **T3 rollback.** From the end of T2, start the old compose again on the
  same volume: cluster comes up and `admin` logs in. (Shows the way back if
  the new config fails on the host.)
- **T4 idempotence.** `--render` twice leaves every file byte-identical;
  `--apply-users` twice exits 0.
- **T5 (optional, skip with a note if your environment refuses it).** In the
  T2 cluster after hardening, the image's shipped `kirk` pair is rejected
  (401/403) on `_plugins/_security/authinfo`. This is a local throwaway
  cluster only; never aim this at anything else.

### Edge-case matrix

| axis | applies | note |
|---|---|---|
| fresh volume / existing volume | yes | T1 / T2; the two paths differ (file-init vs REST) |
| rootless podman, SELinux enforcing (collector) vs podman machine on Windows (local test) | yes | mount options and key ownership; report anything that only the collector can prove |
| host without `openssl` (the collector has none) | yes | container fallback in `--render` |
| clients that skip TLS verification | yes | must keep working untouched; do not "improve" them here |
| sentinel Vector shipping during the restart | no code | runbook item: disk buffer covers minutes |
| second node / transport TLS | no | single node, but transport settings must still be valid or the node will not start |
| password containing `$ " \` or spaces | yes | hash and `.env` handling must not pass it through a shell word |

### Walkthrough (operator)

- **Discover:** `CLAUDE.md` "Changing things" gets a line (orchestrator adds
  it after landing); `./harden-opensearch.sh` with no flags prints usage.
- **Input:** `--render`, recreate the two containers, `--apply-users`,
  `--check`.
- **Feedback:** `--check` prints `ok` / `FAIL` per line; progress lines while
  waiting for health.
- **Failure:** every `FAIL` line says what was expected and what came back;
  `--render` refuses loudly rather than overwrite a key; missing
  `DASHBOARDS_SERVICE_PASSWORD` stops compose with the `:?` message.

### Report

What changed (`path:line`), each test stage with its result and duration,
anything only the collector can prove, and every deviation with its reason.

## After landing (orchestrator + operator)

1. Diff read against this plan; rerun `test-opensearch-hardening.sh`.
2. Paste-ready runbook for the collector sitting (copy files, fix CRLF,
   `--render`, stop/start order, `--apply-users`, `--check`, rollback), the
   operator runs or approves each state-changing step.
3. Only after `--check` passes on the collector: commit and rename this file
   to a tracked name. Done 2026-09-20.
