"""Prompt privately and configure gateway credentials on the authorized host.

The real key crosses only SSH stdin and is stored in a mode-600 host secrets
file. OpenRouter's reported limit must be at most the operator's $5 cap.
"""
import argparse
import getpass
import json
import shlex
import subprocess

REMOTE = r'''
import json,os,pwd,secrets,sys,urllib.request,urllib.error
from pathlib import Path
key=json.load(sys.stdin)['provider_key']
req=urllib.request.Request('https://openrouter.ai/api/v1/key',headers={'Authorization':'Bearer '+key})
try:
    with urllib.request.urlopen(req,timeout=20) as response: data=json.load(response)['data']
except urllib.error.HTTPError as exc:
    raise SystemExit('Provider key check HTTP status '+str(exc.code)) from None
limit=data.get('limit');remaining=data.get('limit_remaining')
if not isinstance(limit,(int,float)) or isinstance(limit,bool) or not 0<limit<=5:
    raise SystemExit('Provider key does not report a spending limit at or below $5')
if remaining is not None and remaining<=0:raise SystemExit('Provider key has no remaining budget')
token=secrets.token_hex(32)
p=Path('/etc/tripwire-model-gateway/gateway-secrets.json')
p.write_text(json.dumps({'provider_key':key,'client_token':token})+'\n')
owner=pwd.getpwnam('modelgateway');os.chown(p,owner.pw_uid,owner.pw_gid);p.chmod(0o600)
env=Path('/home/fakevm/tripwire/beelzebub/.env')
values=dict(line.split('=',1) for line in env.read_text().splitlines() if '=' in line)
values['OPEN_AI_SECRET_KEY']=token
values['LLM_ENDPOINT']='http://model-gateway:8080/v1/chat/completions'
env.write_text(''.join(k+'='+v+'\n' for k,v in values.items()).replace('\\n','\n'))
env.chmod(0o600)
print(json.dumps({'provider_limit_usd':limit,'provider_remaining_usd':remaining,'credentials_installed':True}))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    args = parser.parse_args()
    key = getpass.getpass('Development key (hidden): ')
    if not key or any(c.isspace() for c in key): raise SystemExit('invalid key')
    subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', args.host,
                    'python3 -c ' + shlex.quote(REMOTE)],
                   input=json.dumps({'provider_key': key}).encode(), check=True)


if __name__ == '__main__': main()
