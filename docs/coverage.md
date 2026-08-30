# Coverage on OpenCode 1.18.20

This matrix reports what the checked-in runtime suite observed on the installed OpenCode `1.18.20` binary. “Supported” means the fixture reached the hook with the expected data, the decision changed or permitted the real effect, and correlation was observed. It does not mean every invocation shape or future OpenCode release is covered. The vendored response schema follows open upstream PR #22 at `aae26f823b44a76ec930180aab477da3baa76634`; this remains an implementation-compatibility update, not an ACS-Core claim.

| Boundary | ACS treatment | Status | Evidence and limit |
|---|---|---|---|
| Handshake | `handshake/hello` | Supported | Lazy initialization negotiates ACS `0.1.0`, evaluated methods, timeouts, failure posture, transport, and HMAC support. |
| First governed tool in a session | `steps/sessionStart`, then `steps/toolCallRequest` | Supported | Initialization completes before the first tool decision. OpenCode host IDs are mapped to canonical ACS UUIDs. |
| Session deletion | `steps/sessionEnd` | Partial | A unit test verifies a schema-valid `reason: abandoned` request when `session.deleted` is observed and verifies that recreating the host ID starts a new ACS session. Process exit is not claimed as a reliable end event. |
| Built-in `bash` | Pre-execution `steps/toolCallRequest`; post-execution result | Supported | Real allow and deny side effects verified. Nonzero OpenCode exit metadata maps to ACS `failure`. |
| Built-in `write` | Request and result | Supported | Real allowed write and correlated result verified. |
| Built-in `read` | Request | Supported for deny | Denial occurs before fixture secret content reaches model output. Allow behavior uses the common hook but has no dedicated E2E case. |
| Built-in `edit` | Request | Supported for deny | Denied fixture leaves original file unchanged. |
| Built-in `apply_patch` | Request | Supported for deny | Denied fixture does not create its target. |
| Parallel sibling tool calls | Requests and results | Supported | Two real Bash calls retain distinct ACS request/result references. Guardian requests are serialized per ACS session to preserve chain state. |
| `task` tool | Request at launch | Supported for launch denial only | Denied task does not launch. At the tested `tool.execute.before` boundary OpenCode exposes the parent `sessionID` and invocation `callID`, but no child-session identifier or child lifecycle event. The adapter therefore does not fabricate `steps/subagentStart` or infer child coverage. |
| Plugin-defined custom tool | Request | Supported for tested shape | Fixture receives complete `target` and `content` arguments; denial prevents its file write. Arbitrary third-party behavior is not certified. |
| Local MCP tool exposed by OpenCode | Request | Supported for tested shape | Inert fixture receives complete arguments; denial prevents its file write. This is tool-call coverage, not raw MCP protocol wrapping. |
| Tool result | `steps/toolCallResult` | Supported as observation | Correlated after execution. A later deny cannot undo the action. No policy is enforced at this stage. |
| Bash `MODIFY` | Argument replacement before execution | Supported, opt-in | On `1.18.20`, the replacement command—not the original marker-bearing command—produces the observed content. Only a nonempty replacement for `bash.command` is accepted. |
| File/path/structured `MODIFY` | None | Unsupported | No claim for `read`, `write`, `edit`, `apply_patch`, MCP, custom tools, redactions, or `modified_content`. |
| `ASK` / `DEFER` | Fail closed | Unsupported as continuations | Both decisions become denials. No authenticated remote approval/resume path exists. |
| Direct server `POST /session/:id/shell` | None | Confirmed bypass | The fixture command executes and the Guardian sees zero tool requests. Must be disabled or separately controlled in a deployment. |
| Normal CLI / `opencode run` model tool path | Tool hooks | Supported | This is the primary E2E ingress. |
| Normal server message path | Not separately characterized | Unsupported claim | The direct shell route was separated; normal HTTP message ingress has not received its own checked-in case. |
| Desktop and IDE clients | None claimed | Unsupported claim | They may use the server, but their exact ingress and configuration were not tested. |
| Direct user terminal or other local process | None | Unsupported by design | Outside the enrolled OpenCode process. |
| User message / model response | None | Unsupported | No canonical ACS messages emitted for these boundaries. |
| Compaction / turn lifecycle | None | Unsupported | No canonical ACS messages emitted. |
| Raw MCP protocol | None | Unsupported | `wrapped_protocols` is empty and no ACS MCP profile is claimed. |
| `system/ping` | None | Unsupported | Not advertised because the adapter does not emit it. |
| First-party `acs_protected_append` | Request, capability receipt, remote execution, result | Supported for deployed demo | A signed `ALLOW` carries a 30-second, single-use capability bound to ACS request, session, action, resource, and value. The capability remains in plugin memory. The remote resource accepts it once; no-capability and replay attempts fail. |

## Integrity and failure cases tested

Malformed Guardian JSON, unavailable Guardian during startup with refuse posture, unsigned or invalid decision and JSON-RPC error envelopes in client tests, response/request correlation errors, unsupported Guardian methods, required provenance, oversized responses, `ASK`, and `DEFER` all follow explicit failure behavior. A signed error is authenticated before it is surfaced; a missing or invalid error signature is a signature failure.

## Pending ACS-Core changes in upstream PR #21

PR #21 is open as of this matrix. Nothing here treats its proposed rules as merged or claims ACS-Core conformance.

- The adapter's opt-in Bash-only `MODIFY` remains a narrow extension. If `MODIFY` becomes a SHOULD, it does not make the adapter MODIFY-capable for every tool shape and does not resolve the remaining gaps.
- `system/ping` remains unimplemented. The PR's proposed SHOULD would remove it only as an unconditional profile blocker; this adapter does not yet document or negotiate a liveness alternative.
- `wrapped_protocols` remains empty. A deployment that uses MCP still lacks raw `protocols/MCP/*` coverage, including resource reads; normalized MCP-tool invocation is not protocol wrapping. Only a deployment that genuinely does not use MCP could avoid the proposed conditional requirement.
- OpenCode's `task` launch is gated as a parent tool request, but the tested runtime does not expose an authoritative child session ID at that boundary. The adapter therefore emits no `steps/subagentStart` or `steps/subagentStop` and makes no vacuity claim for a runtime that does expose a task/subagent abstraction.
- User-message and agent-response coverage, authenticated ASK/DEFER continuations, complete session lifecycle, SessionContext persistence, and profile-level end-to-end evidence are still absent.

## Revalidation rule

The version is deliberately pinned in code and tests. An OpenCode upgrade must rerun the full runtime suite before this table is updated. A hook firing is insufficient by itself: the test must observe the intended execution or non-execution effect and its audit correlation.

## Remote protected-resource checkpoint — 2026-08-29

The optional remote E2E case ran against a private HTTPS deployment through Tailscale Serve. It observed an allowed OpenCode call create a server-side event, a denied call create none, a direct unauthenticated resource request return 401, and a consumed capability replay return 409. The service was active, bound only to loopback, with a root-only server environment and a resource database owned by its unprivileged service account.

This verifies the capability-gated API path, not exclusive authority over the deployment host: the workstation operator also has administrative SSH access, and the adapter does not sandbox OpenCode from the workstation user's credentials.
