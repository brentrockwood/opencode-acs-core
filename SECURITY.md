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

Enforce mode requires HMAC-SHA256 request and response authentication. Session keys are derived from configured input key material and the canonical ACS session UUID. Keys are read from an environment variable named in configuration and are never accepted in the Guardian URL. The adapter refuses non-loopback plaintext HTTP in enforce mode.

HMAC authenticates a peer that knows the shared secret; it does not establish independent operator identity. Production key injection and rotation are deployment responsibilities. A production deployment should use HTTPS even on networks considered private.

Requests include UUID request IDs, timestamps, nonces, and session chain hashes when returned by the Guardian. This adapter verifies response correlation and signatures. Guardian-side freshness, replay storage, key rotation, and durable audit retention are not implemented here.

## Failure behavior

Enforce mode requires the startup posture to be explicit. Under `refuse`, an unavailable or invalid Guardian blocks tool execution. After a successful handshake, the Guardian's negotiated `on_decision_failure` value selects proceed or deny behavior. Every fail-open event is written to the configured audit sink when possible.

`ASK` and `DEFER` fail closed. There is no fallback to a local approval prompt because that would not be independent authorization. `MODIFY` fails closed unless it is enabled and contains exactly one supported Bash command replacement.

## Audit privacy

Payload bodies are omitted by default because tool arguments and results can contain source code, credentials, user data, and file contents. Enabling payloads is an explicit privacy decision. The optional local JSONL file is controlled by the same local operator and is not tamper-resistant evidence.

## Protected resources

[docs/protected-resource.md](docs/protected-resource.md) describes both the local semantics fixture and a deployed remote demonstration. The remote service keeps its capability-signing key on the deployment host, binds only to loopback, and is exposed through private HTTPS. The local adapter receives a separate Guardian client key and never receives the resource-signing key.

This establishes the remote capability flow and keeps the resource-signing key off the workstation. It does not establish that the enrolled process lacks every other authorization path. The workstation operator retains administrative SSH access to the deployment host; because OpenCode is not sandboxed from that user's files and credentials, an unsupported ingress or another local process may be able to use SSH to reconfigure or bypass the service. Stronger process- or human-operator claims require credential isolation and separate administration.

## Reporting

Do not include Guardian keys, captured payloads, or sensitive workspace data in a report. This repository currently has no published security contact or coordinated disclosure commitment.
