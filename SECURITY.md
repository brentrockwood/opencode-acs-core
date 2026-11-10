# Security and trust boundary

## The boundary this adapter provides

The plugin is a policy-enforcement point inside an enrolled OpenCode process. The Guardian is the policy-decision point. For model-routed calls that OpenCode sends through `tool.execute.before`, the plugin authenticates a canonical ACS request, verifies the Guardian's signed response, and applies a supported decision before the tool executes.

That can reduce accidental or model-originated misuse in an enrolled process. It does not protect the local machine from its operator.

## Trusted and untrusted components

The deployment trusts:

- the Guardian's policy, signing key custody, availability choice, and audit operation;
- the OpenCode binary and this plugin while the enrolled process is running;
- any remote resource or capability broker claimed as the consequential enforcement point.

The design does not trust model output, tool arguments, MCP or custom-tool input, or network responses that fail ACS validation and signature verification. A hostile local operator remains outside the protection this plugin can provide because that operator can change the binary, configuration, plugin source, environment, filesystem, or network path.

The Pi extension and this OpenCode plugin have the same fundamental local-operator boundary: either can be removed by an operator who controls the agent process.

## Confirmed bypasses and gaps

- OpenCode `1.18.20`'s direct `POST /session/:id/shell` route executes a shell command without reaching the plugin's model-tool prehook. The runtime test records a real side effect and zero Guardian tool requests.
- Commands run directly in a user's terminal or another local process are outside the adapter by design.
- A denied `task` launch proves only that the parent launch was stopped. It proves nothing about already-running or independently launched child sessions.
- Session start is emitted lazily before the first governed tool. Session end is attempted only when OpenCode emits `session.deleted`; normal process termination is not claimed as a complete lifecycle signal.
- User-message, model-response, compaction, desktop-specific ingress, command routing, and raw MCP protocol traffic are not covered.
- Result handling is observational and cannot roll back an executed side effect.

Deployments that expose the OpenCode server must separately disable or isolate unsupported routes. Local OpenCode permissions are useful defense in depth, but they are not the remote Guardian authority and a local operator can change them.

## Transport and keys

Enforce mode requires HMAC-SHA256 request and response authentication. Session keys use HKDF-SHA256 with empty salt, the exact transmitted ACS session ID as UTF-8 info without normalization, and 32-byte output. Configured secrets are literal UTF-8 text and must contain at least 32 bytes from a cryptographically secure random source, not a passphrase. Length is checked; randomness cannot be checked. Keys are read from an environment variable named in configuration and are never accepted in the Guardian URL. The adapter refuses non-loopback plaintext HTTP in enforce mode.

HMAC authenticates a peer that knows the shared secret; it does not establish independent operator identity. Production key injection and rotation are deployment responsibilities. A production deployment should use HTTPS even on networks considered private.

Requests include UUID request IDs, timestamps, nonces, and session chain hashes when returned by the Guardian. This adapter verifies response correlation and signatures. Guardian-side freshness, replay storage, key rotation, and durable audit retention are not implemented here.

## Failure behavior

A failed Guardian exchange is resolved by what failed, not only by the configured posture. The pinned specification distinguishes a Guardian that answered from one that did not (§4.1, §6.4). This adapter applies the split the maintainers set out on upstream issue #32 on 2026-11-04 and 2026-11-05 as documented local policy:

- **No usable answer** follows the configured posture: a silent Guardian past the timeout, a connection or TLS failure, an HTTP 408 or 5xx without a JSON-RPC body, or an authenticated `-32603` internal error.
- **A refusal blocks under either posture**: any authenticated JSON-RPC error other than `-32603`, including `SESSION_REFUSED`, `UNSUPPORTED_VERSION` and `PROVENANCE_REQUIRED`, and any other HTTP 4xx without a JSON-RPC body. A JSON-RPC error carried on a non-2xx status is read and verified before the status is used.
- **An integrity failure blocks under either posture**: a missing or invalid signature, an unexpected key label, a JSON-RPC id or `request_id` mismatch, a malformed or oversized response (a malformed `allow` included), an unsupported decision, or a request this adapter could not form validly.

`startupPosture` applies to a handshake that gets no usable answer and defaults to `refuse`: an unavailable Guardian then blocks tool execution and records `acs_startup_refused`; under the local opt-in `proceed` the session starts unguarded and records `acs_session_unguarded`. A handshake refusal or an unverifiable handshake refuses the session under either value. After a successful handshake, the effective posture for a step that gets no usable answer is the local `decisionFailurePosture` (default `deny`, or `proceed` when `startupPosture` is `proceed`) as tightened by the Guardian's negotiated `on_decision_failure`: the Guardian can turn a local `proceed` into `deny`, a Guardian `proceed` never loosens a local `deny`, and an omitted field leaves the local value in force. `deny` blocks; `proceed` records `acs_fail_open` and allows. Observe mode never blocks. The post-tool result hook remains observational in every case.

Two consequences deserve a direct statement. A request payload above the advertised 1 MiB limit is a local request fault: the Guardian never sees it, so in enforce mode the step blocks under either posture, where it previously failed open under `proceed`. A success body on a failure status is contradictory and is treated as an integrity failure rather than honored. Host-handler records label a non-adapter error's `failure_kind` as `other`, not `transport`.

The fail-safe default was adopted on 2026-11-10 as local policy: default-deny enforcement, local opt-in to availability fail-open, and a Guardian that can tighten but not loosen that choice. It follows the direction of the upstream proposal on issue #32, which has not merged into the pinned specification text; no conformance to that proposal is claimed. Before this change the adapter used the Guardian's `on_decision_failure` as the step posture and treated an omitted field as `proceed`, so a deployment with `startupPosture: refuse` whose Guardian omits the field now denies on step outages where it previously failed open; set `decisionFailurePosture: proceed` to restore that behavior deliberately. Every failed exchange is recorded under both postures with its failure class, its disposition (`availability`, `refusal` or `integrity`), the effective `posture` and, when present, the JSON-RPC error code or HTTP status. Without a file path, failure records go to stderr; a failed file write also falls back to stderr without changing enforcement. Operators must capture stderr or provide a writable audit file. This is not a durable-delivery guarantee.

`ASK` and `DEFER` fail closed. There is no fallback to a local approval prompt because that would not be independent authorization. `MODIFY` fails closed unless it is enabled and contains exactly one supported Bash command replacement.

## Audit privacy

Payload bodies and message text are omitted by default because tool arguments, results and Guardian error text can contain source code, credentials, user data, and file contents. Enabling payloads is an explicit privacy decision that also writes message text. The optional local JSONL file is controlled by the same local operator and is not tamper-resistant evidence.

Without `audit.path`, decision-failure records are written to stderr. When a configured file cannot be written, the record also falls back to stderr. The stderr fallback always omits payload and message text, including when an opted-in file sink fails. Failure class, kind, disposition and correlation IDs remain available in every record.

## Protected resources

[docs/protected-resource.md](docs/protected-resource.md) describes both the local semantics fixture and a deployed remote demonstration. The remote service keeps its capability-signing key on the deployment host, binds only to loopback, and is exposed through private HTTPS. The local adapter receives a separate Guardian client key and never receives the resource-signing key.

This establishes the remote capability flow and keeps the resource-signing key off the workstation. It does not establish that the enrolled process lacks every other authorization path. The workstation operator retains administrative SSH access to the deployment host; because OpenCode is not sandboxed from that user's files and credentials, an unsupported ingress or another local process may be able to use SSH to reconfigure or bypass the service. Stronger process- or human-operator claims require credential isolation and separate administration.

## Reporting

Do not include Guardian keys, captured payloads, or sensitive workspace data in a report. This repository currently has no published security contact or coordinated disclosure commitment.

