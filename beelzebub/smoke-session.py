"""On-host synthetic state/isolation test. Output is operator-authored only."""
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict, deque
import json
import os
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent

def main():
    askpass=HERE/'session.local.askpass.py'
    askpass.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nprint(dict(l.split("=",1) for l in Path(__file__).with_name(".env").read_text().splitlines() if "=" in l)["BAIT_PASSWORD"])\n')
    askpass.chmod(0o700)
    log=Path('/var/log/tripwire-fakevm/beelzebub.log')
    before={json.loads(l).get('event',{}).get('ID') for l in log.read_text().splitlines()}
    commands={}
    for label in ('alpha','beta'):
        commands[label]=['mkdir -p /tmp/tripwire_'+label, 'cd /tmp/tripwire_'+label,
                         "echo 'fixture_"+label+"' > marker", 'cat marker', 'pwd', 'ls',
                         'cp marker copy', 'mv copy moved', 'cat moved',
                         'rm moved', 'ls', 'cd /does-not-exist', 'pwd']
    def run(lines):
        return subprocess.run(['ssh','-T','-p','2222','-o','ConnectTimeout=10',
            '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(HERE/'session.local.known_hosts'),
            '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
            '-o','NumberOfPasswordPrompts=1','deploy@127.0.0.1'],
            input=('\n'.join(lines)+'\nexit\n').encode(),capture_output=True,timeout=90,
            start_new_session=True,env=os.environ|{'SSH_ASKPASS':str(askpass),'SSH_ASKPASS_REQUIRE':'force','DISPLAY':':0'})
    try:
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(run,commands.values()))
        for label,result in zip(commands,results):
            assert result.returncode==0
            assert ('deploy@web01:/tmp/tripwire_'+label+'$ ').encode() in result.stdout,'prompt did not follow cd'
        commands['fresh']=['pwd','ls /tmp','uptime']
        result=run(commands['fresh']);assert result.returncode==0
    finally:
        askpass.unlink(missing_ok=True)
    time.sleep(.5)
    events=[json.loads(l).get('event',{}) for l in log.read_text().splitlines()]
    sessions=[]
    for label,lines in commands.items():
        starts=[e for e in events if e.get('Status')=='Start' and e.get('ID') not in before]
        matching=[]
        for start in starts:
            interactions=[e for e in events if e.get('ID')==start['ID'] and e.get('Status')=='Interaction']
            # Upstream tracer workers can write same-session events out of
            # order. Compare multiplicities; SSH output verifies the prompt.
            if Counter(e['Command'] for e in interactions)==Counter(lines):matching.append((start,interactions))
        assert len(matching)==1
        start,interactions=matching[0]
        by_command=defaultdict(deque)
        for e in interactions:by_command[e['Command']].append(e.get('CommandOutput','').strip())
        outputs=[by_command[line].popleft() for line in lines]
        if label=='fresh':
            assert outputs[:2]==['/home/deploy',''],'reconnect leaked filesystem or directory'
            assert outputs[2] and 'temporarily unavailable' not in outputs[2] and outputs[2]!='command not found'
        else:
            directory='/tmp/tripwire_'+label
            expected=['','','','fixture_'+label,directory,'marker','','','fixture_'+label,'','marker','cd: /does-not-exist: No such file or directory',directory]
            assert outputs==expected,'virtual state mismatch'
        sessions.append({'session':start['ID'],'commands':lines,'outputs':outputs,'events':len(lines)+2})
    result={'passed':True,'sessions':sessions}
    (HERE/'session-result.local.json').write_text(json.dumps(result)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
