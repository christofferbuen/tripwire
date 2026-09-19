"""Real Vector -> OpenSearch integration on an internal disposable Podman network.

No host ports, production access, secrets or paid model calls. Requires the
helper image and synthetic engine logs produced by test-local.py.
Security is disabled inside this unpublished test network. GeoIP uses an
empty pipeline fixture because this test does not download GeoIP databases.
This verifies transport and mappings, not authentication or enrichment.
"""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('engine_test', HERE / 'test-local.py')
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)
podman = local.podman

PROBE = r'''
import importlib.util,json,sys,time,urllib.request,urllib.error
from pathlib import Path
def api(method,path,body=None):
    req=urllib.request.Request('http://opensearch:9200'+path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type':'application/json'},method=method)
    with urllib.request.urlopen(req,timeout=5) as r:return json.load(r)
phase=sys.argv[1]
if phase=='setup':
    for _ in range(90):
        try:
            if api('GET','/_cluster/health')['status'] in ('green','yellow'):break
        except (OSError,urllib.error.URLError):pass
        time.sleep(1)
    else:raise RuntimeError('OpenSearch did not become ready')
    template=json.loads(Path('/work/template.json').read_text())
    api('PUT','/_ingest/pipeline/tripwire-enrich',{'description':'local transport test; GeoIP not exercised','processors':[]})
    api('PUT','/_index_template/tripwire-fakevm',template)
    api('PUT','/tripwire-fakevm-000001',{'aliases':{'tripwire-fakevm':{'is_write_index':True}}})
    actual=api('GET','/tripwire-fakevm-000001/_mapping')['tripwire-fakevm-000001']['mappings']
    spec=importlib.util.spec_from_file_location('verify','/work/verify-collector.py')
    verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)
    assert verify.normalize_mapping(template['template']['mappings'])==verify.normalize_mapping(actual)
    changed=json.loads(json.dumps(actual));changed['properties']['fakevm']['properties']['command']['type']='keyword'
    assert verify.normalize_mapping(changed)!=verify.normalize_mapping(actual)
    changed=json.loads(json.dumps(actual));changed['dynamic']='true'
    assert verify.normalize_mapping(changed)!=verify.normalize_mapping(actual)
    print('PASS real OpenSearch mapping normalization; changed field types and open mappings remain unequal',flush=True)
else:
    lines=[json.loads(line) for line in Path('/work/beelzebub.log').read_text().splitlines()]
    events=[r['event'] for r in lines if 'event' in r and r['event'].get('Protocol')=='SSH']
    for _ in range(60):
        result=api('POST','/tripwire-fakevm/_search',{'size':1000,'track_total_hits':True})
        if result['hits']['total']['value']>=len(events):break
        time.sleep(1)
    assert result['hits']['total']['value']==len(events), 'lost or duplicated engine events'
    docs=[hit['_source'] for hit in result['hits']['hits']]
    assert {'start','interaction','end','stateless'}<={d['fakevm']['status'] for d in docs}
    by_session={}
    for doc in docs:by_session.setdefault(doc['fakevm']['session'],[]).append(doc)
    assert any({'start','interaction','end'}<={d['fakevm']['status'] for d in group} for group in by_session.values())
    assert any(d['fakevm']['command']=='whoami' and d['fakevm']['output'].strip()=='deploy' for d in docs)
    assert all('source' not in d for d in docs if d['fakevm']['status']=='end')
    assert all('message' not in d and 'event' in d for d in docs)
    print('PASS real engine logs -> actual Vector transform -> OpenSearch alias: '+str(len(docs))+' events, session correlation and command/output preserved',flush=True)
'''


def main():
    logs = HERE / 'capture.local.logs/beelzebub.log'
    assert logs.is_file(), 'Run test-local.py first'
    script = (ROOT / 'bootstrap-opensearch.sh').read_text()
    base = re.search(r"tripwire_template=\"\$\(cat <<'EOF'\n(.*?)\nEOF", script, re.S)[1]
    generator = re.search(r"fakevm_template=.*?python3 -c '(.*?)'\)", script, re.S)[1]
    template = subprocess.check_output([sys.executable, '-c', generator], input=base.encode())
    config = (ROOT / 'vector-fakevm.toml').read_text()
    config = config.replace('/var/log/tripwire-fakevm/beelzebub.log', '/work/beelzebub.log')
    config = config.replace('SECRET[local.opensearch_endpoint]', 'http://opensearch:9200')
    config = re.sub(r'auth\.strategy = .*\n|auth\.user = .*\n|auth\.password = .*\n', '', config)
    config = 'data_dir = "/tmp"\n' + config
    prefix = 'tw-fakevm-os-' + uuid.uuid4().hex[:8]
    network, volume = prefix + '-net', prefix + '-data'
    helper, server, vector = prefix + '-helper', prefix + '-os', prefix + '-vector'
    try:
        podman('network', 'create', '--internal', network)
        podman('volume', 'create', volume)
        podman('run', '-d', '--name', helper, '--network', network, '-v', volume + ':/work',
               'localhost/tripwire-beelzebub-test:local', 'sleep', '600')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'template.json').write_bytes(template)
            (path / 'vector.toml').write_text(config, newline='\n')
            (path / 'probe.py').write_text(PROBE, newline='\n')
            (path / 'verify-collector.py').write_bytes((HERE / 'verify-collector.py').read_bytes())
            (path / 'beelzebub.log').write_bytes(logs.read_bytes())
            podman('cp', str(path) + '/.', helper + ':/work')
        podman('run', '-d', '--name', server, '--network', network, '--network-alias', 'opensearch',
               '--memory', '2g', '--pids-limit', '512', '--ulimit', 'nofile=65536:65536',
               '-e', 'discovery.type=single-node', '-e', 'node.store.allow_mmap=false',
               '-e', 'DISABLE_INSTALL_DEMO_CONFIG=true', '-e', 'DISABLE_SECURITY_PLUGIN=true',
               '-e', 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m',
               'docker.io/opensearchproject/opensearch:3.8.0')
        print(podman('exec', helper, 'python3', '/work/probe.py', 'setup', timeout=120).stdout, flush=True)
        podman('run', '-d', '--name', vector, '--network', network, '-v', volume + ':/work:ro',
               'docker.io/timberio/vector:0.58.0-alpine', '--config', '/work/vector.toml')
        print(podman('exec', helper, 'python3', '/work/probe.py', 'verify', timeout=90).stdout, flush=True)
    finally:
        podman('rm', '-f', vector, server, helper, check=False)
        podman('volume', 'rm', volume, check=False)
        podman('network', 'rm', network, check=False)


if __name__ == '__main__':
    main()
