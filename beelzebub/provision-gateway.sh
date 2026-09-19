#!/usr/bin/env bash
# Provision the private gateway; credentials and activation are separate steps.
set -euo pipefail
umask 077
source_dir=$(cd "$(dirname "$0")" && pwd)
if ! id modelgateway >/dev/null 2>&1; then useradd --system --user-group --no-create-home --shell /usr/sbin/nologin modelgateway; fi
install -d -m 755 /opt/tripwire-model-gateway
install -m 644 "$source_dir/gateway.py" /opt/tripwire-model-gateway/gateway.py
install -d -m 700 -o modelgateway -g modelgateway /etc/tripwire-model-gateway
for name in gateway-relay.py compose.gateway.yaml; do
    install -m 600 -o fakevm -g fakevm "$source_dir/$name" "/home/fakevm/tripwire/beelzebub/$name"
done
cat > /etc/systemd/system/tripwire-model-gateway.service <<'UNIT'
[Unit]
Description=Private fixed-origin Tripwire model gateway
After=network-online.target
Wants=network-online.target
[Service]
User=modelgateway
Group=fakevm
RuntimeDirectory=tripwire-model-gateway
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=restart
ExecStartPre=/usr/bin/rm -f /run/tripwire-model-gateway/gateway.sock
ExecStart=/usr/bin/python3 /opt/tripwire-model-gateway/gateway.py --secrets /etc/tripwire-model-gateway/gateway-secrets.json --socket /run/tripwire-model-gateway/gateway.sock
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=128M
TasksMax=16
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemd-analyze verify /etc/systemd/system/tripwire-model-gateway.service
systemctl daemon-reload
printf 'PASS gateway files and service provisioned; not activated\n'
