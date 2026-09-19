"""Build a secret-free LF-normalized deployment bundle; never contacts hosts."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
FILES = ('bootstrap-opensearch.sh', 'enrich.py', 'droppers.py', 'alerts.py', 'dashboards.py')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-enricher-sha256', required=True,
                        help='Reviewed deployed baseline; accounts for old test-fixture-only drift')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert len(args.expected_enricher_sha256) == 64
    int(args.expected_enricher_sha256, 16)
    manifest, payload = {}, {}
    for name in FILES:
        content = (ROOT / name).read_bytes().replace(b'\r\n', b'\n')
        old = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=ROOT)
        before = hashlib.sha256(old.replace(b'\r\n', b'\n')).hexdigest()
        if name == 'enrich.py':
            before = args.expected_enricher_sha256
        manifest[name] = {'before': before, 'after': hashlib.sha256(content).hexdigest()}
        payload[name] = content
    for name in ('deploy-collector.sh', 'verify-collector.py'):
        payload[name] = (ROOT / 'beelzebub' / name).read_bytes().replace(b'\r\n', b'\n')
    payload['manifest.json'] = json.dumps(manifest, indent=2).encode() + b'\n'
    with tarfile.open(args.out, 'w:gz') as archive:
        for name, content in payload.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o600
            archive.addfile(info, io.BytesIO(content))
    print('Bundle SHA256:', hashlib.sha256(args.out.read_bytes()).hexdigest())
    print('Files:', ', '.join(payload))


if __name__ == '__main__':
    main()
