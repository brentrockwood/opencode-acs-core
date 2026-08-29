# Remote protected-resource service

This directory contains the exact service deployed for the OpenCode ACS protected-resource demonstration.

## Deployment

The installer expects Debian with Python 3, systemd, Tailscale, and passwordless sudo for the deploying account. It is idempotent with respect to secrets: rerunning it replaces code and the unit but preserves an existing `/etc/opencode-acs-demo.env`.

The source may be staged under the deployment user's home directory. The installed layout is:

- `/opt/opencode-acs-demo/server.py` — root-owned service code;
- `/etc/opencode-acs-demo.env` — root-owned mode `0600`, including both server secrets;
- `/var/lib/opencode-acs-demo/state.sqlite3` — service-owned request, replay, and event state;
- `$HOME/.config/opencode-acs-demo/client.env` — mode `0600`, containing only the Guardian client key and key ID;
- `/etc/systemd/system/opencode-acs-demo.service` — hardened systemd unit.

The backend listens on a loopback-only port. Tailscale Serve terminates private HTTPS and proxies to that listener. Confirm that the target host has no pre-existing Serve configuration before running the installer, because the example claims the default HTTPS route.

## Operations

Use `systemctl status opencode-acs-demo.service` and `journalctl -u opencode-acs-demo.service` for health and logs. `tailscale serve status` shows the private HTTPS route. `/healthz` exposes only a static health response.

The resource intentionally has no read API. Verification of protected events is performed administratively against SQLite. Service logs contain request paths and statuses but not request bodies or capabilities.

The ACS client key may be copied to a temporary local environment for testing. The resource capability-signing key must remain only in `/etc/opencode-acs-demo.env`. Rotate both server-side secrets and restart the service if either is disclosed; rotating the client key also requires replacing the local client environment.

## Scope

The fixed demo policy denies every tool except `acs_protected_append`, denies protected values containing `deny`, and issues a capability for other nonempty values up to 512 bytes. This is not a general policy engine.

The server is separate from the OpenCode process, but the workstation may retain a sudo-capable SSH path to the deployment host. Because the adapter is not a credential sandbox, do not use this deployment as evidence that the local process or human operator lacks all bypass paths.
