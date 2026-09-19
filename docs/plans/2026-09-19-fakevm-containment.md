# Narrow fake-VM containment: review proposal

Status: design proposal only. No firewall implementation or host commands
are authorized by this document. Full package D remains deferred.

## Scope and ownership

Proposed owner files: `contain-fakevm.sh` (new), supporting tests under
`beelzebub/`, and the fake-VM deployment runbook. Do not modify
`harden-sentinel.sh`, administrative SSH, inbound/forward chains, WireGuard,
sysctls, service masks or reboot settings. Coordinate any later edits to
`compose.fakevm.yaml` with the engine package; no concurrent ownership.

This replaces D's broad deployment gate only if the operator approves the
narrower threat boundary and the tests below pass. It confines processes
owned by the separate fake-VM Unix user and subordinate UIDs; it does not
confine an attacker who becomes root on the VM. It must never be described
as equivalent to the full host/cloud-firewall design.

## Proposed mechanism

- Dedicated output-hook nftables table. Default accept for unrelated UIDs;
  packets belonging to the fake-VM user/range enter a restricted chain.
  Never flush existing tables or alter input/forward policy.
- Permit replies to incoming SSH sessions. Match reply direction as well
  as established state; do not allow arbitrary established outbound flows.
  Stop all fake-VM processes before first apply, then verify from the actual
  container network configuration rather than assuming socket ownership.
- Permit DNS only to explicitly chosen resolvers. Permit model HTTPS only
  to a refreshed, expiring IPv4/IPv6 address set for the chosen provider.
  Drop and rate-limit logs for other destinations, including loopback,
  link-local/metadata endpoints, private networks and the collector.
- CDN IP allowlisting permits other sites on the same CDN addresses. A
  hostname-enforcing proxy is needed if the approved boundary requires one
  exact HTTPS origin. Upstream also lacks an explicit model-call timeout;
  resolve this in the same design review rather than claiming SSH timeout
  cancels an HTTP request.
- Log with the existing egress event format and prove delivery through
  Vector/OpenSearch/ntfy. Start the watcher separately without applying D.
- Render first, syntax-check, snapshot only the owned table/units, arm a
  rollback timer, apply atomically and confirm from a fresh SSH session.
  Persist only after confirmation. A failed refresh must close model egress.

## Acceptance tests written before implementation

1. Rendered rules contain no input/forward hooks, SSH configuration, tunnel
   changes, sysctls, service masks or reboot policy. Other UIDs are unaffected.
2. Apply/rollback modifies only owned table and units; syntax failure changes
   nothing. A missing user/range/resolver/destination refuses to apply.
3. Real fake-VM bridged and any proposed host-network mode: arbitrary public
   TCP/UDP, private/collector, metadata, IPv6 and loopback connections fail;
   provider requests and incoming SSH replies work. Check actual packet UID.
4. A connection made before applying does not remain an unrestricted
   established outbound path. Test namespace/user-switch and forwarding
   attempts within the unprivileged container's actual capabilities.
5. Current SSH remains usable, a fresh SSH login works, and sentinel traffic
   and log shipping continue. These tests are mandatory despite narrow scope.
6. The blocked attempt appears in the event log, OpenSearch and phone alert.
   Flooded attempts stay bounded and blocking persists after log rate limits.
7. Rollback timer restores the prior state. Confirmation persists it. Verify
   service startup order and a controlled reboot with the cloud console open.
8. Expire provider addresses and fail DNS refresh: model calls fail closed;
   existing SSH access and sentinel telemetry remain available.
9. Slow model responses are bounded independently of the SSH session and
   cannot accumulate indefinitely. Test timeouts and response-size limits.

## Edge cases and walkthrough

| Case | Required result |
|---|---|
| Provider shares CDN addresses | State the residual reachability; review proxy option |
| Rootless helper owns the socket | Match observed UID/range, not guessed process UID |
| IPv6 available | Filter/test it or omit its model allowance explicitly |
| Existing outbound socket | No generic established-flow bypass |
| User or subnet changes | Validation fails until configuration is reviewed |
| Model slow or unresponsive | Independent bounded request lifetime |
| Reboot before confirmation | Prior state retained; no public fake shell starts |
| Reboot after confirmation | Containment precedes fake-shell startup |

Operator reviews this boundary and the endpoint-timeout solution first.
Implementation then produces rendered files and local tests for review.
Only afterward provide exact read-only VM checks for approval, followed by
one approved write step at a time with the cloud console open. Public fake
SSH exposure and deploy bait activation are the final steps.

## Proposed model gateway for review

The reviewed upstream client has no request deadline or completion-token
limit. A fixed-origin completion gateway is the proposed solution while
retaining the unmodified engine image. This is design only, not approval
to implement or deploy it.

The engine may reach only the gateway. The gateway may reach only the
configured provider over verified HTTPS; client-supplied URLs, model names,
authorization headers and redirects cannot select another destination.
The real provider key belongs to the gateway, not the engine. Authentication
between engine and gateway uses a separate local credential. Run the gateway
under a separately confined identity so the engine cannot inherit its wider
egress permission by making its own outbound socket.

Proposed initial limits: 64 KiB request body, 128 KiB provider response,
512 completion tokens, two concurrent provider calls and a 30-second total
request lifetime including connection and body reads. Use a worker process
with an externally enforced lifetime; a socket timeout alone can be extended
indefinitely by trickled response bytes. Reject excess work immediately.
Keep the original system prompt and latest command, bound retained history,
and reject malformed or oversized input before opening an upstream socket.
Do not log authorization headers or request bodies in gateway diagnostics.

Tests must exercise a stalled connection, trickled body, oversized body,
redirect, model/endpoint substitution, concurrency overload, disconnect,
worker cleanup and provider failure. No test needs a paid API call. A small
operator-approved real request is a later compatibility check.

This does not repair the engine's in-memory history growth or its context
key of client IP plus username. Document context sharing across reconnects
and NAT, preserve the container memory bound, and evaluate whether the
accepted upstream-image constraint needs to change if strict session
isolation becomes required. A gateway bounds provider requests; it must not
be claimed to fix upstream history ownership or memory allocation.
