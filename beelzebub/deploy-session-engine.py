"""Load a tested image and replace only the private engine, with rollback.

Requires operator authorization for private host changes. No SSH/firewall edits.
Archive and immutable image ID must come from the same local build.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

HERE=Path(__file__).resolve().parent

REMOTE=r'''
import json,os,pwd,shlex,shutil,subprocess,time
from pathlib import Path
root=Path('/home/fakevm/tripwire')
owner=pwd.getpwnam('fakevm')
def run(command):
    return subprocess.run(['su','-','fakevm','-c','export XDG_RUNTIME_DIR=/run/user/$(id -u); cd ~/tripwire; '+command],check=True,capture_output=True,text=True)
image=run('podman image inspect --format {{.Id}} '+shlex.quote(payload['image'])).stdout.strip()
assert image.removeprefix('sha256:')==payload['image'].removeprefix('sha256:'),'loaded image mismatch'
backup=root/('session-backup.local.'+str(time.time_ns()));backup.mkdir(mode=0o700)
paths=['beelzebub/.env','beelzebub/compose.session.yaml','beelzebub/smoke-session.py']
existing=[]
for item in paths:
    source=root/item
    if source.exists():shutil.copy2(source,backup/source.name);existing.append(item)
base='podman-compose --env-file beelzebub/.env -f compose.fakevm.yaml -f beelzebub/compose.private.yaml -f beelzebub/compose.gateway.yaml'
stage='prepare'
try:
    env=root/'beelzebub/.env'
    lines=[line for line in env.read_text().splitlines() if not line.startswith('FAKEVM_SESSION_IMAGE=')]
    env.write_text('\n'.join(lines)+'\nFAKEVM_SESSION_IMAGE='+payload['image']+'\n')
    for name,text in payload['files'].items(): (root/'beelzebub'/name).write_text(text)
    for item in paths:
        path=root/item;path.chmod(0o600);os.chown(path,owner.pw_uid,owner.pw_gid)
    stage='recreate'
    run(base+' -f beelzebub/compose.session.yaml up -d --no-deps --force-recreate fakevm')
    time.sleep(2)
    # Only this helper's generated key cache is reset after engine recreation.
    (root/'beelzebub/session.local.known_hosts').unlink(missing_ok=True)
    stage='smoke'
    result=run('python3 beelzebub/smoke-session.py')
    print(result.stdout,end='')
    print(json.dumps({'deployment':'passed','backup':str(backup)}))
except Exception as exc:
    # Compose may include local credentials in its diagnostics. Keep them in
    # the root-only backup, never forward raw stderr into the operator chat.
    diagnostic=backup/'failure.txt'
    diagnostic.write_text(str(getattr(exc,'stdout',''))+'\n'+str(getattr(exc,'stderr','')))
    diagnostic.chmod(0o600)
    for item in paths:
        target=root/item
        if item in existing:
            shutil.copy2(backup/target.name,target);os.chown(target,owner.pw_uid,owner.pw_gid)
        else:target.unlink(missing_ok=True)
    previous=base+(' -f beelzebub/compose.session.yaml' if 'beelzebub/compose.session.yaml' in existing else '')
    run(previous+' up -d --no-deps --force-recreate fakevm')
    raise SystemExit('Private engine update failed at '+stage+'; previous configuration restored. Private diagnostics: '+str(diagnostic))
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',required=True)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',args.image):parser.error('immutable sha256 image ID required')
    ssh=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',args.host]
    with args.archive.open('rb') as stream:
        subprocess.run(ssh+["su - fakevm -c 'export XDG_RUNTIME_DIR=/run/user/$(id -u); podman load'"],stdin=stream,check=True)
    payload={'image':args.image,'files':{name:(HERE/name).read_text(encoding='utf-8') for name in ['compose.session.yaml','smoke-session.py']}}
    script='payload='+repr(payload)+'\n'+REMOTE
    subprocess.run(ssh+['python3 -'],input=script.encode(),check=True)

if __name__=='__main__':main()
