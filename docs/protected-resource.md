# Protected-resource demonstrations

The host plugin cannot take authority away from an operator who controls every relevant process and credential. This project therefore has two deliberately different demonstrations: a local capability-semantics fixture and a deployed process-separation test on a remote host.

## Local semantics fixture

`examples/protected-resource-demo.ts` models three roles:

1. The Guardian returns a correlated ACS `ALLOW` for a named operation.
2. An issuer turns only that allow decision into a short-lived capability.
3. A resource performs the operation only after verifying and consuming that capability.

The token binds a random capability ID, ACS request ID, subject, action, resource, issuance time, and expiry. Tests cover valid use, replay, wrong action, expiry, forgery, and attempted issuance from a denied decision. This fixture runs in one process and establishes semantics only.

## Deployed remote demonstration

The source under `remote/` installs a combined Guardian/issuer and protected append-only demonstration resource:

- `opencode-acs-demo.service` runs as an unprivileged, non-login system user.
- The Python service binds only to `127.0.0.1:8788`.
- Tailscale Serve exposes it through private HTTPS within the tailnet; no public listener is required.
- `/etc/opencode-acs-demo.env` is root-owned mode `0600` and holds two independent secrets.
- The workstation receives the Guardian HMAC client key. It never receives the resource capability-signing key.
- SQLite stores processed ACS request IDs, consumed capability IDs, and protected events under `/var/lib/opencode-acs-demo`.

For `acs_protected_append`, the Guardian policy either denies or returns `ALLOW` with a capability. The capability binds the canonical ACS request and session, fixed `append` action, fixed demonstration resource, SHA-256 of the value, 30-second expiry, and random one-time ID. The plugin keeps it in memory and the tool sends it directly to the configured resource endpoint.

The checked-in optional runtime test establishes:

- an allowed real OpenCode tool call produces a server-side event;
- a Guardian denial prevents the tool and no denied value appears in the resource database;
- calling the resource without a capability returns HTTP 401;
- the first use of a valid capability returns HTTP 201;
- replaying that capability returns HTTP 409.

At the verification checkpoint, the database contained allowed events and zero events whose value matched the deny marker. Counts are intentionally not treated as stable because each rerun appends new test evidence.

## What this does and does not establish

The deployed service and its resource-signing key are outside the OpenCode process. The test therefore demonstrates a consequential capability-gated API path whose normal operation is enforced remotely.

It does not prove exclusive remote authority. The workstation operator retains administrative SSH access to the deployment host. OpenCode is not an operating-system sandbox, so another local process or an unsupported OpenCode ingress may be able to use that standing credential to reconfigure the service or mutate its database. The test also does not establish institutional independence, workload attestation, revocation before expiry, multi-host availability, or tamper-resistant audit ownership.

Stronger claims require a server administrator separate from the local operator, removal of the local operator's standing administrative credential, and independently retained audit evidence.
