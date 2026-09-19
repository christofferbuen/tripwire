"""Execute an explicitly approved collector batch, with binary SSH transport."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    content = args.bundle.read_bytes()
    assert hashlib.sha256(content).hexdigest() == args.sha256, 'approved bundle changed'
    expected = {'bootstrap-opensearch.sh', 'enrich.py', 'droppers.py', 'alerts.py',
                'dashboards.py', 'deploy-collector.sh', 'verify-collector.py', 'manifest.json'}
    with tarfile.open(args.bundle) as archive:
        members = archive.getmembers()
        assert len(members) == len(expected) and {m.name for m in members} == expected
        assert all(m.isfile() for m in members)
    command = ('umask 077; stage=$(mktemp -d "$HOME/tripwire-fakevm-stage-XXXXXXXX") && '
               'tar -xz -C "$stage" && bash "$stage/deploy-collector.sh"')
    subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
                    '-o', 'StrictHostKeyChecking=yes', args.host, command],
                   input=content, check=True)


if __name__ == '__main__':
    main()
