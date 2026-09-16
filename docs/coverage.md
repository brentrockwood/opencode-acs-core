# Coverage on OpenCode 1.18.20

This matrix reports what the checked-in runtime suite observed on the installed OpenCode `1.18.20` binary. “Supported” means the fixture reached the hook with the expected data, the decision changed or permitted the real effect, and correlation was observed. It does not mean every invocation shape or future OpenCode release is covered. The vendored schema follows open upstream PR #21 at `b865e510e17165258fb65810938086217b28c7ae`, which proposes repository release `0.1.3`. Reference-adapter behavior is tracked at open PR #22 head `7174a033c15f69ee58caaa5eb0a19279592171c7`. Neither pin is an ACS-Core claim.

| Boundary | ACS treatment | Status | Evidence and limit |
|---|---|---|---|
| Handshake | `handshake/hello` | Supported | Lazy initialization accepts the schema's direct `ServerHello` response and negotiates ACS `0.1.0`, evaluated methods, timeouts, failure posture, transport, and HMAC support. |
| First governed tool in a session | `steps/sessionStart`, then `steps/toolCallRequest` | Supported | Initialization completes before the first tool decision. OpenCode host IDs are mapped to canonical ACS UUIDs. |
| Session deletion | `steps/sessionEnd` | Partial | A unit test verifies a schema-valid `reason: abandoned` request when `session.deleted` is observed and verifies that recreating the host ID starts a new ACS session. Process exit is not claimed as a reliable end event. |
| Built-in `bash` | Pre-execution `steps/toolCallRequest`; post-execution result | Supported | Real allow and deny side effects verified. Nonzero OpenCode exit metadata maps to ACS `failure`. |
| Built-in `write` | Request and result | Supported | Real allowed write and correlated result verified. |
| Built-in `read` | Request | Supported for deny | Denial occurs before fixture secret content reaches model output. Allow behavior uses the common hook but has no dedicated E2E case. |
| Built-in `edit` | Request | Supported for deny | Denied fixture leaves original file unchanged. |
| Built-in `apply_patch` | Request | Supported for deny | Denied fixture does not create its target. |
| Parallel sibling tool calls | Requests and results | Supported | Two real Bash calls retain distinct ACS request/result references. Guardian requests are serialized per ACS session to preserve chain state. |
| Fresh foreground `task` | `steps/subagentStart`; child session lifecycle; successful `steps/subagentStop` | Supported for tested shape | Before execution, the adapter allocates the child ACS UUID and uses the start request ID as `parent_step_id`; DENY prevents OpenCode from creating the child. On ALLOW, OpenCode's `session.created` event identifies the child by `parentID` and its task-derived title. The adapter binds that host ID to the allocated ACS session before the child's first tool call. A successful foreground result carries the same child ID in task metadata and emits `subagentStop`. |
| Concurrent fresh `task` launches from one parent | None for the ambiguous launch | Mode-dependent | Until the preceding child has appeared in `session.created`, a second task from the same parent cannot be assigned safely from `parentID` alone. Enforce mode denies it. Observe mode allows execution, records the launch and result as unmapped, and emits neither fabricated subagent lifecycle evidence nor a generic task-result event. |
| Resumed `task` | `steps/toolCallRequest` / `steps/toolCallResult` | Unsupported subagent-lifecycle claim | A `task_id` resumes an existing child rather than creating the fresh session required by `subagentStart`; this path retains the generic parent tool mapping. |
| Fresh background or failed/cancelled `task` | Partial subagent lifecycle | Unsupported terminal-lifecycle claim | A fresh background task can pass the start gate and bind its child, but completion is not exposed through the tested successful foreground `tool.execute.after` path. Failed and cancelled termination are likewise not mapped, so complete `subagentStop` coverage is not claimed. |
| Plugin-defined custom tool | Request | Supported for tested shape | Fixture receives complete `target` and `content` arguments; denial prevents its file write. Arbitrary third-party behavior is not certified. |
| Local MCP tool exposed by OpenCode | Request | Supported for tested shape | Inert fixture receives complete arguments; denial prevents its file write. This is tool-call coverage, not raw MCP protocol wrapping. |
| Built-in `skill` tool | Generic `steps/toolCallRequest` / `steps/toolCallResult` | Supported as a tool gate; no skill-lifecycle claim | The pre-execution hook exposes the requested skill name, and the successful result exposes rendered content plus `name` and `dir` metadata. It does not provide a prior approved registration, a stable id plus digest over the complete loadable artifact, or an unload boundary. The adapter therefore does not fabricate `skillRegister`, `skillLoad`, or `skillUnload`. |
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

OpenCode's SDK also exposes `Session.parentID` and `session.children({ path: { id } })`. Enumeration confirms that child identity is available after creation, but it cannot by itself provide a decision gate before creation. The adapter therefore allocates the ACS child ID at `tool.execute.before` and uses the pushed `session.created` relationship for the time-sensitive binding; the task result's `metadata.sessionId` is an independent completion-side check.

## Integrity and failure cases tested

Malformed Guardian JSON, unavailable Guardian during startup with refuse posture, unsigned or invalid decision and JSON-RPC error envelopes in client tests, response/request correlation errors, unsupported Guardian methods, required provenance, oversized responses, `ASK`, and `DEFER` all follow explicit failure behavior. A signed ordinary-method error is authenticated before it is surfaced; a missing or invalid error signature is a signature failure. `system/ping` errors remain exempt because the pinned schema says the liveness method must not require a signature. Current PR #22 reference adapters also sign ordinary errors, although the current schema does not define an explicit `error.signature` property. Requiring it for non-ping methods when the session key is available is deliberate conservative interoperability behavior, not a conformance claim.

## Proposed ACS-Core 0.1.3 changes in upstream PR #21

PR #21 is open and awaiting re-review as of 2026-09-15. Nothing here treats its proposed rules as merged or claims ACS-Core conformance.

- The adapter's opt-in Bash-only `MODIFY` remains a narrow extension. Under the proposal, `MODIFY` is SHOULD-support; unsupported shapes must normally become `DENY` with audit, with a special `postCompact` exception. The adapter fails closed on unsupported tool modifications but does not implement the whole proposed contract.
- `system/ping` remains unimplemented. The proposal makes it SHOULD-support but requires a deployment-named alternative when omitted. This adapter does not configure or assert such an alternative, so this remains a proposed Core gap.
- `wrapped_protocols` remains empty. The proposal requires wrapped coverage whenever a session involves MCP, except that MCP `tools/call` may use generic tool hooks. OpenCode's normalized tool hook does not expose resource reads, prompts, notifications, or negotiation, so only a deployment that genuinely never uses MCP could omit the namespace.
- Fresh `task` launches use decision-eligible `steps/subagentStart`, and the tested runtime binds the resulting `parentID` child session before its first tool call. This addresses the proposal's MUST-emit spawn gate for the tested shape. Successful foreground completion emits the proposed SHOULD-level `steps/subagentStop`; resume, background completion, and failure/cancellation termination remain incomplete and are not claimed.
- Skill lifecycle hooks are SHOULD-emit when observable. The built-in `skill` tool remains governed as a generic tool call because its plugin hooks do not supply the prior registration and complete-artifact digest needed to bind an honest `skillLoad`, or any unload boundary.
- User-message and agent-response coverage, authenticated ASK/DEFER continuations, complete session lifecycle, SessionContext persistence, and profile-level end-to-end evidence are still absent.

## Revalidation rule

The version is deliberately pinned in code and tests. An OpenCode upgrade must rerun the full runtime suite before this table is updated. A hook firing is insufficient by itself: the test must observe the intended execution or non-execution effect and its audit correlation.

## Remote protected-resource checkpoint — 2026-08-29

The optional remote E2E case ran against a private HTTPS deployment through Tailscale Serve. It observed an allowed OpenCode call create a server-side event, a denied call create none, a direct unauthenticated resource request return 401, and a consumed capability replay return 409. The service was active, bound only to loopback, with a root-only server environment and a resource database owned by its unprivileged service account.

This verifies the capability-gated API path, not exclusive authority over the deployment host: the workstation operator also has administrative SSH access, and the adapter does not sandbox OpenCode from the workstation user's credentials.
