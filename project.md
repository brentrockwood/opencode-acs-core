# OpenCode ACS adapter — implementation checkpoint

## Outcome

The adapter now demonstrates a real ACS enforcement point inside OpenCode `1.18.20`. A deterministic local provider drives the installed OpenCode binary, a signed loopback Guardian decides the call, and tests verify the resulting filesystem effects.

The implementation proves more coverage than the initial investigation justified, but it also found a concrete bypass: OpenCode's direct session-shell endpoint does not traverse the model-tool hook. That keeps the security claim where it belongs. The adapter governs an enrolled model-tool path; it does not control OpenCode universally or protect a local machine from its operator.

## Completed phases

### Phase 0 — Runtime and schema contract

- TypeScript package and pinned dependencies created.
- OpenCode `1.18.20` asserted by the runtime test.
- The reviewed ACS v0.1 schema revision is vendored locally so the repository installs and tests without the Pi adapter.
- Canonical requests, responses, handshake payloads, and hook payloads are validated offline.
- A deterministic OpenAI-compatible model fixture drives actual OpenCode tool calls.

### Phase 1 — Consequential tool boundary

- Signed Guardian client implements timeout, size limits, schema validation, response correlation, version negotiation, chain state, and explicit failure posture.
- Real `ALLOW` and `DENY` effects are covered for Bash; file-tool denial and write allowance are also exercised.
- Audit records bind canonical session IDs, OpenCode host session/call IDs, ACS request IDs, method, tool, decision/failure, result status, and component versions. Payloads are omitted by default.
- First-tool initialization and parallel sibling correlations are tested. Task launch can be denied, without claiming child-session coverage.

### Phase 2 — Bypass, custom, MCP, and modification probes

- Direct `/session/:id/shell` is a verified bypass and is documented as unsupported.
- A plugin-defined custom tool and an inert local MCP tool reach the hook with complete fixture arguments and are denyable before their effects.
- Bash argument replacement reaches actual execution on `1.18.20`. It is opt-in and restricted to a complete `command` replacement. File, structured, MCP, and custom-tool modifications remain unsupported.

### Phase 3 — Protected-resource architecture and remote deployment

- A capability fixture separates an allowed ACS decision from capability issuance and resource verification.
- Tokens are short-lived, single-use, signed, and bound to request, subject, action, and resource.
- Tests cover allow, deny, replay, wrong action, expiry, and forgery.
- A private remote service now separates ACS decision/capability issuance from the protected append resource. The resource-signing key remains server-only.
- A real OpenCode call created a remote event with a 30-second, request/session/action/resource/value-bound capability. Denial created no matching event, a no-capability request returned 401, and replay returned 409.
- The service runs unprivileged, binds only to loopback, persists replay/event state in SQLite, and is exposed through Tailscale Serve HTTPS.
- Exclusive process and hostile-human-operator authority remain explicitly unclaimed: the workstation retains administrative SSH access to the deployment host, and this adapter is not a credential sandbox.

### Phase 4 — Escalation and claim review

- `ASK` and `DEFER` fail closed. They remain unsupported because no authenticated remote approval continuation exists.
- `MODIFY` is enabled only for the runtime-proven Bash shape.
- README, security guidance, and the coverage matrix avoid claims of containment, universal interception, ACS conformance, OpenCode endorsement, OWASP endorsement, or hostile-operator resistance.

## Boundary conclusion

The Pi extension and OpenCode plugin share the same local-operator weakness: an operator with control of the agent process can remove either one. Moving the Guardian elsewhere protects policy and decision operation, but it does not by itself protect local effects. Taking authority away requires the consequential resource or execution capability to be enforced somewhere the local operator does not control.

## Release state

The code is suitable as an experimental standalone adapter repository and reproducible runtime probe. The remote deployment completes the capability-gated API demonstration, but it is a fixed test policy and not an exclusively controlled production Guardian. The repository no longer depends on the Pi checkout; npm publication remains unauthorized, and the remote service remains a demonstration rather than an independently administered production authority.

The definitive boundary-by-boundary status is in `docs/coverage.md`.
