# OpenCode ACS adapter

This is an experimental Agent Control Standard (ACS) v0.1 plugin for OpenCode. It gives an enrolled OpenCode process a remote Guardian decision point at the tool hook OpenCode exposes.

The useful claim is narrow: on OpenCode `1.18.20`, a signed Guardian decision can allow, deny, or—only for Bash commands and only when explicitly enabled—replace a model-routed tool invocation before the real host executes it. The test suite exercises the actual OpenCode binary and checks observable side effects.

It is not a sandbox. An operator who controls OpenCode can remove the plugin, use a different process, or call OpenCode's direct server-shell route, which the runtime test confirms bypasses this hook. Independent authority requires the protected resource or execution service to live outside that operator's control.

## What is proven on 1.18.20

- `ALLOW` and `DENY` at the pre-execution hook for built-in `bash`, `read`, `edit`, `write`, and `apply_patch` calls.
- A fresh foreground `task` is gated as `steps/subagentStart`; denial prevents child creation, while an allowed child is bound through OpenCode's `parentID` session relationship before its first tested tool call. Successful foreground completion emits `steps/subagentStop`. Resume, background completion, and failed/cancelled termination remain outside this claim.
- Plugin-defined custom tools and an inert local MCP tool reach the same hook with complete fixture arguments and can be denied before their side effects.
- Allowed results reach `steps/toolCallResult` and retain their request correlation.
- Parallel sibling calls retain distinct request/result correlations.
- Malformed output, an unavailable Guardian under refuse posture, and unsupported `ASK`/`DEFER` decisions fail closed.
- A Guardian-modified Bash command reaches execution when `enableModify` is true; no other modification shape or tool family is supported.
- `POST /session/:id/shell` executes without a `steps/toolCallRequest`. It is an explicit bypass.
- The first-party `acs_protected_append` tool obtains a signed, value-bound, 30-second capability from the Guardian and uses it at a private remote resource. The capability stays in plugin memory rather than model-visible arguments.

See [docs/coverage.md](docs/coverage.md) for the full matrix and [SECURITY.md](SECURITY.md) for the trust boundary.

## Development setup

This repository carries its own reviewed ACS v0.1 schema copy and has no checkout-time dependency on the Pi adapter. Publication remains a separate decision; the package is intended to install and test from an isolated checkout.

```sh
npm install
npm run typecheck
npm test -- --exclude test/opencode-runtime.e2e.test.ts
npm run test:e2e
```

The runtime suite starts only deterministic loopback fixtures. It uses no external model or Guardian credentials, but it does invoke the `opencode` binary on `PATH` and verifies that it reports `1.18.20`. Set `OPENCODE_E2E_BIN` to test another executable location.

For a manual loopback demonstration, set `OPENCODE_ACS_HMAC_KEY`, point a local copy of the example configuration at `http://127.0.0.1:8787/`, and run `npm run demo:guardian`. The demo allows requests except Bash commands containing `ACS_DEMO_DENY`. It is a protocol fixture, not a policy engine or remote authority.

## Project-plugin setup

Create `.opencode/plugins/acs.ts` in the enrolled workspace:

```ts
export { AcsPlugin } from "/absolute/path/to/acs-core/opencode/src/index.ts";
```

Copy [examples/config.json](examples/config.json) to `.opencode/acs-core.json`, replace the endpoint and key names, then provide the HMAC key through the configured environment variable. Enforce mode requires both a key environment-variable name and a key ID. Non-loopback Guardian endpoints must use HTTPS.

When `protectedResource` is configured, the plugin also registers `acs_protected_append`. A signed Guardian `ALLOW` must include a capability before the tool can execute. The fixed resource endpoint then verifies the capability independently. See [examples/remote-config.json](examples/remote-config.json) and [docs/protected-resource.md](docs/protected-resource.md).

No configuration means no plugin behavior. `observe` mode never blocks. `enforce` mode requires an explicit `startupPosture`; `refuse` is the example posture.

## Decisions

`ALLOW` executes the original invocation. `DENY` throws before execution. `ASK` and `DEFER` are denied because the adapter has no authenticated remote approval continuation. `MODIFY` is disabled by default and accepts only a complete, nonempty replacement for `bash.command`.

The post-tool hook is observational. A Guardian response to `steps/toolCallResult` cannot undo a side effect that already occurred.

## Audit data

The optional JSONL audit sink records timestamps, adapter/OpenCode/ACS versions, canonical and host session correlation, ACS request IDs, OpenCode call IDs, method, tool, decision or normalized failure, and observed exit status. Payload bodies are replaced with `[omitted]` unless `audit.includePayloads` is explicitly enabled.

Local audit writing is passive: a write failure does not change an enforcement decision. A deployment that needs independently owned evidence must send evidence to an independently operated service.

## Status

This is an experimental adapter, not an official OpenCode integration, not an OWASP-endorsed implementation, and not a claim of ACS conformance. It is not being published to npm as part of this work.

The deployed demonstration establishes the remote capability protocol and withholds the resource-signing key from OpenCode. It does not establish that the workstation lacks another authorization path: the workstation operator retains administrative SSH access to the deployment host, and an unsandboxed process running as that user may be able to use it. The demonstrated claim is therefore the enrolled ACS tool path, not resistance to the local process or human operator through every available route.
