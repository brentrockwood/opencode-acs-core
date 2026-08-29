#!/usr/bin/env bash
set -euo pipefail

service_user=opencode-acs-demo
install_root=/opt/opencode-acs-demo
state_root=/var/lib/opencode-acs-demo
environment_file=/etc/opencode-acs-demo.env
deployment_user=${SUDO_USER:-$(id -un)}
deployment_group=$(id -gn "${deployment_user}")
deployment_home=$(getent passwd "${deployment_user}" | cut -d: -f6)
if [[ -z "${deployment_home}" ]]; then
  echo "Unable to determine deployment home directory" >&2
  exit 1
fi
client_directory=${deployment_home}/.config/opencode-acs-demo
client_file=${client_directory}/client.env

if ! id -u "${service_user}" >/dev/null 2>&1; then
  sudo useradd --system --home-dir "${state_root}" --shell /usr/sbin/nologin "${service_user}"
fi

sudo install -d -o root -g root -m 0755 "${install_root}"
sudo install -d -o "${service_user}" -g "${service_user}" -m 0700 "${state_root}"
sudo install -o root -g root -m 0755 server.py "${install_root}/server.py"
sudo install -o root -g root -m 0644 opencode-acs-demo.service /etc/systemd/system/opencode-acs-demo.service

if ! sudo test -f "${environment_file}"; then
  sudo python3 - "${environment_file}" <<'PY'
import secrets
import sys

path = sys.argv[1]
with open(path, "x", encoding="utf-8") as output:
    output.write(f"ACS_DEMO_CLIENT_KEY={secrets.token_urlsafe(48)}\n")
    output.write("ACS_DEMO_CLIENT_KEY_ID=opencode-acs-demo-client\n")
    output.write(f"ACS_DEMO_RESOURCE_KEY={secrets.token_urlsafe(48)}\n")
    output.write("ACS_DEMO_HOST=127.0.0.1\n")
    output.write("ACS_DEMO_PORT=8788\n")
    output.write("ACS_DEMO_DATABASE=/var/lib/opencode-acs-demo/state.sqlite3\n")
PY
  sudo chmod 0600 "${environment_file}"
  sudo chown root:root "${environment_file}"
fi

install -d -m 0700 "${client_directory}"
sudo python3 - "${environment_file}" "${client_file}" <<'PY'
import os
import sys

source, destination = sys.argv[1:]
values = {}
with open(source, encoding="utf-8") as input_file:
    for line in input_file:
        key, value = line.rstrip("\n").split("=", 1)
        values[key] = value
temporary = destination + ".tmp"
with open(temporary, "w", encoding="utf-8") as output:
    output.write(f"ACS_GUARDIAN_HMAC_KEY={values['ACS_DEMO_CLIENT_KEY']}\n")
    output.write(f"ACS_GUARDIAN_KEY_ID={values['ACS_DEMO_CLIENT_KEY_ID']}\n")
os.chmod(temporary, 0o600)
os.replace(temporary, destination)
PY
sudo chown "${deployment_user}:${deployment_group}" "${client_file}"
chmod 0600 "${client_file}"

sudo systemctl daemon-reload
sudo systemctl enable --now opencode-acs-demo.service
sudo tailscale serve --bg --yes http://127.0.0.1:8788

for _ in $(seq 1 20); do
  if curl --fail --silent http://127.0.0.1:8788/healthz >/dev/null; then
    break
  fi
  sleep 0.25
done
curl --fail --silent http://127.0.0.1:8788/healthz >/dev/null
sudo systemctl --no-pager --full status opencode-acs-demo.service | head -20
sudo tailscale serve status
