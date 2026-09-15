# Vendored Agent Control Standard schemas

- Upstream: <https://github.com/GenAI-Security-Project/agent-control-standard>
- Revision: `b865e510e17165258fb65810938086217b28c7ae` (upstream PR #21 head; not merged at vendoring time)
- Upstream release baseline: `0.1.2`; PR #21 proposes repository release `0.1.3`
- Schema version: `0.1.0`
- Retrieved: 2026-09-15
- License: Apache License 2.0

The complete `specification/v0.1.0` schema directory is copied without local
modification. `acs_schema.json` is the upstream aggregator from that directory.

The current upstream PR #22 head, `7174a033c15f69ee58caaa5eb0a19279592171c7`,
contains reference adapters but no normative schema changes. In particular,
signed JSON-RPC error envelopes remain reference-adapter behavior rather than
an explicit `error.signature` property in the schema. The schema still accepts
that property because `JsonRpcError` does not close additional properties.
