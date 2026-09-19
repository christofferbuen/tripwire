"""Run one deterministic private SSH session; keep the bait password local."""
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', action='store_true', help='Run one synthetic model-backed command')
    parser.add_argument('--semantics', action='store_true', help='Check unknown commands and basic shell output through the model')
    parser.add_argument('--state', action='store_true', help='Check directory changes and silent commands through the model')
    parser.add_argument('--refresh-host-key', action='store_true', help='Reset only the generated smoke-test known-hosts file after an approved engine recreation')
    args = parser.parse_args()
    commands = ['ls /var/www'] if args.model else ['whoami', 'pwd', 'id']
    if args.semantics:
        commands = ['hello', 'tripwire_no_such_command', 'echo hello', "printf '%s\\n' tripwire", 'ls /var/www']
    if args.state:
        commands = ['cd /home/deploy', 'pwd', 'cd /tmp', 'pwd', 'echo $PWD', 'cd ..', 'pwd', 'true', 'cd /home/deploy']
    if args.refresh_host_key:
        (HERE / 'known_hosts.local.ssh').unlink(missing_ok=True)
    askpass = HERE / 'smoke.local.askpass.py'
    askpass.write_text('#!/usr/bin/python3\nfrom pathlib import Path\np=Path(__file__).with_name(".env")\nprint(dict(line.split("=",1) for line in p.read_text().splitlines() if "=" in line)["BAIT_PASSWORD"])\n')
    askpass.chmod(0o700)
    since = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    logfile = Path('/var/log/tripwire-fakevm/beelzebub.log')
    previous_ids = {json.loads(line).get('event', {}).get('ID') for line in logfile.read_text().splitlines()} if logfile.exists() else set()
    try:
        result = subprocess.run([
            'ssh', '-T', '-p', '2222', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=' + str(HERE / 'known_hosts.local.ssh'),
            '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1', 'deploy@127.0.0.1'],
            input=('\n'.join(commands) + '\nexit\n').encode(), capture_output=True, timeout=300 if args.state else 180 if args.semantics else 40,
            start_new_session=True,
            env=os.environ | {'SSH_ASKPASS': str(askpass), 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': ':0'})
    finally:
        askpass.unlink(missing_ok=True)
    assert result.returncode == 0, 'private SSH failed; inspect service state without printing credentials'
    if not args.model and not args.semantics and not args.state:
        assert all(x in result.stdout for x in (b'deploy', b'/home/deploy', b'uid=1001(deploy)')), 'static replies missing'
    time.sleep(0.5)
    events = [json.loads(line).get('event', {}) for line in Path('/var/log/tripwire-fakevm/beelzebub.log').read_text().splitlines()]
    starts = [event for event in events if event.get('Status') == 'Start' and event.get('User') == 'deploy'
              and event.get('ID') not in previous_ids
              and datetime.fromisoformat(event['DateTime'].replace('Z', '+00:00')) >= datetime.fromisoformat(since)]
    assert len(starts) == 1, 'expected exactly one new private session'
    session = starts[0]['ID']
    summary = {'session': session, 'since': since, 'commands': commands, 'ssh_passed': True}
    if args.state:
        interactions = [event for event in events if event.get('ID') == session and event.get('Status') == 'Interaction']
        expected = ['', '/home/deploy', '', '/tmp', '/tmp', '', '/', '', '']
        summary['outputs'] = [event.get('CommandOutput', '')[:512] for event in interactions]
        print(json.dumps(summary), flush=True)
        assert [event['Command'] for event in interactions] == commands, 'state-test commands missing or reordered'
        assert [event.get('CommandOutput', '').strip() for event in interactions] == expected, 'working-directory or silent-command behavior failed'
    if args.model:
        interactions = [event for event in events if event.get('ID') == session and event.get('Status') == 'Interaction']
        assert len(interactions) == 1 and interactions[0].get('Command') == commands[0]
        output = interactions[0].get('CommandOutput', '')
        assert output.strip() and output.strip() != 'command not found', 'model request failed'
        summary['model_output'] = output[:512]
    if args.semantics:
        interactions = [event for event in events if event.get('ID') == session and event.get('Status') == 'Interaction']
        outputs = {event['Command']: event.get('CommandOutput', '') for event in interactions}
        assert len(interactions) == len(commands), 'missing semantic-test interactions'
        summary['outputs'] = {command: outputs[command][:512] for command in commands}
        # Print only this operator-created test, even on a failed assertion.
        print(json.dumps(summary), flush=True)
        for command in commands[:2]:
            assert command + ': command not found' in outputs[command], 'unknown command semantics failed'
        assert outputs['echo hello'].strip() == 'hello', 'echo semantics failed'
        assert outputs[commands[3]].strip() == 'tripwire', 'printf semantics failed'
        assert not outputs['ls /var/www'].lstrip().startswith('- '), 'ls returned Markdown bullets'
    (HERE / 'smoke-result.local.json').write_text(json.dumps(summary) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
