#!/usr/bin/env bash
# Operator-authorized private smoke deployment; run as root on the sentinel.
set -euo pipefail
umask 077
bundle=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ]
id sentinel >/dev/null
if ! id fakevm >/dev/null 2>&1; then useradd -m -s /bin/bash fakevm; fi
chmod 700 /home/fakevm
loginctl enable-linger fakevm
systemctl start "user@$(id -u fakevm).service"
asfake() { su - fakevm -c 'export XDG_RUNTIME_DIR=/run/user/$(id -u); export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus; cd ~/tripwire; '"$1" < /dev/null; }
assentinel() { su - sentinel -c 'export XDG_RUNTIME_DIR=/run/user/$(id -u); cd ~/tripwire; '"$1" < /dev/null; }
install -d -m 700 -o fakevm -g fakevm /home/fakevm/tripwire /home/fakevm/tripwire/beelzebub
for file in sentinel.py compose.fakevm.yaml; do install -m 600 -o fakevm -g fakevm "$bundle/$file" "/home/fakevm/tripwire/$file"; done
for file in render.py beelzebub.yaml ssh.yaml.tmpl prompt.txt; do install -m 600 -o fakevm -g fakevm "$bundle/beelzebub/$file" "/home/fakevm/tripwire/beelzebub/$file"; done
install -d -m 750 -o fakevm -g fakevm /var/log/tripwire-fakevm
setfacl -m u:sentinel:rx,d:u:sentinel:r-x /var/log/tripwire-fakevm
python3 - <<'PY'
from pathlib import Path
import os,pwd,secrets
root=Path('/home/fakevm/tripwire/beelzebub')
env=root/'.env'
if not env.exists():
    env.write_text('BAIT_PASSWORD='+secrets.token_hex(16)+'\nSERVER_NAME=web01\nFAKEVM_BIND=127.0.0.1\nFAKEVM_PORT=2222\nOPEN_AI_SECRET_KEY=\n')
    owner=pwd.getpwnam('fakevm');os.chown(env,owner.pw_uid,owner.pw_gid);env.chmod(0o600)
(root/'compose.private.yaml').write_text('services:\n  fakevm:\n    container_name: tripwire-fakevm\n    networks: [private]\nnetworks:\n  private:\n    internal: true\n')
owner=pwd.getpwnam('fakevm');os.chown(root/'compose.private.yaml',owner.pw_uid,owner.pw_gid)
PY
asfake 'python3 beelzebub/render.py --env beelzebub/.env --out beelzebub/runtime.local.config'
asfake 'podman compose --env-file beelzebub/.env -f compose.fakevm.yaml -f beelzebub/compose.private.yaml up -d'
asfake 'podman inspect --format "engine running={{.State.Running}}" tripwire-fakevm'
python3 - <<'PY'
from pathlib import Path
import os,pwd
root=Path('/home/fakevm/.config/systemd/user');root.mkdir(parents=True,exist_ok=True)
unit=root/'tripwire-fakevm.service'
unit.write_text('[Unit]\nDescription=Private Tripwire fake SSH\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/podman start tripwire-fakevm\nExecStop=/usr/bin/podman stop -t 10 tripwire-fakevm\n[Install]\nWantedBy=default.target\n')
owner=pwd.getpwnam('fakevm')
for p in [root.parent.parent,root.parent,root,unit]:os.chown(p,owner.pw_uid,owner.pw_gid)
PY
asfake 'systemctl --user daemon-reload && systemctl --user enable --now tripwire-fakevm.service'
cat > /etc/logrotate.d/tripwire-fakevm <<'ROTATE'
/var/log/tripwire-fakevm/beelzebub.log {
    su fakevm fakevm
    daily
    maxsize 1M
    rotate 3
    missingok
    notifempty
    copytruncate
}
ROTATE
logrotate --debug /etc/logrotate.d/tripwire-fakevm >/dev/null 2>&1
backup=$(mktemp -d /home/sentinel/tripwire-backup-fakevm-XXXXXXXX)
cp -p /home/sentinel/tripwire/compose.sentinel.yaml "$backup/compose.sentinel.yaml"
chown -R sentinel:sentinel "$backup"
install -m 600 -o sentinel -g sentinel "$bundle/vector-fakevm.toml" /home/sentinel/tripwire/vector-fakevm.toml
python3 - <<'PY'
from pathlib import Path
p=Path('/home/sentinel/tripwire/compose.sentinel.yaml');s=p.read_text()
old='command: ["--config", "/etc/vector/vector.toml"]'
new='command: ["--config", "/etc/vector/vector.toml", "--config", "/etc/vector/vector-fakevm.toml"]'
assert s.count(old)==1, 'unexpected Vector command; inspect before editing'
s=s.replace(old,new)
anchor='      - ./vector-sentinel.toml:/etc/vector/vector.toml:ro,Z\n'
assert s.count(anchor)==1
s=s.replace(anchor,anchor+'      - ./vector-fakevm.toml:/etc/vector/vector-fakevm.toml:ro,Z\n      - /var/log/tripwire-fakevm:/var/log/tripwire-fakevm:ro\n')
p.write_text(s)
PY
before=$(assentinel 'podman inspect --format "{{.Id}}" sentinel')
if ! assentinel 'podman compose -f compose.sentinel.yaml up -d --no-deps --force-recreate vector'; then
    cp -p "$backup/compose.sentinel.yaml" /home/sentinel/tripwire/compose.sentinel.yaml
    assentinel 'podman compose -f compose.sentinel.yaml up -d --no-deps --force-recreate vector'
    exit 1
fi
after=$(assentinel 'podman inspect --format "{{.Id}}" sentinel')
[ "$before" = "$after" ]
printf 'PASS private engine started; Vector recreated; original sentinel container preserved\n'
