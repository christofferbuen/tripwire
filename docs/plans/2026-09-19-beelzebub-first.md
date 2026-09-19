# Beelzebub first: proposed sequencing change

Status: local preparation approved by the operator on 2026-09-19. Host
actions still require approval of each exact step. Full hardening remains
deferred. Local results and deviations: beelzebub/README.md.

## Objective and change to the existing plans

Get the fake SSH service ready without first applying package D or completing
SMTP STARTTLS. After approval, replace E's prohibition on starting local work
with a deployment gate: local implementation and isolated stub tests may run
before D and A2. Public deployment still requires verified containment.

The existing D switches ADMIN_SOURCES=any and SSHD_HARDEN=no do not isolate
the change to outbound filtering: D still installs input/forward rules,
updates WireGuard and changes other host settings. Do not apply D as a
shortcut to this work.

## Packages and ownership fences

1. Engine preparation: E's builder files only: beelzebub/,
   compose.fakevm.yaml and vector-fakevm.toml. Follow E's configuration,
   static persona, log whitelist and resource limits. Verify the upstream
   source, image digest, configuration and model compatibility before using
   them; the old plan's upstream claims are hypotheses until checked.
2. Collection integration: E's orchestrator files only:
   bootstrap-opensearch.sh, alerts.py, dashboards.py, enrich.py,
   droppers.py, compose.sentinel.yaml and README.md. Follow E's field
   contract and closed mapping. Review the diff after engine tests establish
   the actual log format.
3. Bait: sentinel.py and compose.sentinel.yaml, after package 2 releases
   the compose file. Extract A2's HTTP bait feature and its relevant tests;
   defer its SMTP and TLS refactor. Preserve wire goldens with bait disabled.
   Keep the deploy credential out of the served bait until the service is
   ready and containment passes. No bait contents in the repository.
4. Deployment containment: a separate plan, reviewed before implementation.
   Scope outbound restrictions to the fake-VM Unix user and subordinate
   UIDs, with a dedicated rollback mechanism. Do not change sshd, inbound
   or forwarding policy, WireGuard configuration, sysctls or reboot settings.
   Design must account for IPv4, IPv6, rootless networking, DNS, local and
   collector destinations, pre-existing connections, provider CDN limits,
   logging and persistence. This is an alternative to D's broader gate,
   requiring explicit review; it is not implemented by D's current flags.

Do not overlap owner files. No commit or push unless requested. Every landing
requires a diff review and a deviations-and-reasons report.

## Acceptance tests

- Engine: E T1-T9 against a local fixed-response model stub; no real API
  key. Check actual forwarding requests, not merely whether ssh -N remains
  running. Test both SFTP-based and legacy SCP requests. Report unavailable
  container tests as blocked, never as passing.
- Integration: real generated engine logs feed Vector tests; validate
  whitelist, truncation, malformed input rejection, mappings, enrichment,
  dropper extraction and bait-used monitor. Use existing selftests where
  applicable and one focused check per added behavior.
- Bait: default WIRE_GOLDEN unchanged; enabled GET/HEAD, query string,
  keep-alive, unreadable and oversized file checks from A2. No SMTP wire
  changes. All new fields have template and live-index mappings.
- Deployment: separate user cannot read sentinel or shipper secrets;
  model calls work while unauthorized outbound attempts fail and produce
  alerts. Test from the actual container network configuration, across
  IPv4/IPv6 and local/collector destinations. Verify rollback, fresh admin
  SSH login, continuing telemetry and containment after reboot before
  exposing the fake shell. Exact commands require operator approval.

## Edge cases

| Case | Required outcome |
|---|---|
| Model down, slow, out of credit | Bounded error; no alternate destination |
| Provider address changes | Reviewed refresh mechanism; fail closed |
| Prompt injection or terminal escapes | Text only; escaped inspection; no secrets in prompt |
| Password mismatch or rotation | Anchored match; bait and engine agree before exposure |
| Rootless helper hides IP or changes socket UID | Detect with real tests; revise plan before deployment |
| Forwarding, file transfer or command execution exists upstream | Stop and report; do not trust the old design claim |
| Containment or rollback test fails | Keep public deployment blocked |
| Restart/reboot | Persistent containment; report SSH host-key behavior |

## Operator walkthrough

Review this sequencing proposal first. Then build locally and report the
tested service, remaining limitations and diffs. Review the separate narrow
containment plan before any host changes. Create a dedicated provider key
with an operator-set spending limit and store it only on the host. Approve
each exact deployment step with the cloud console available, verify access
and containment, then open the decoy service and enable its bait. PTR,
HTTPS, SMTP STARTTLS and broader hardening can follow separately.
