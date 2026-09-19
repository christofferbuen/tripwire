"""Read-only verification, run inside the existing collector enricher."""
import base64
import json
import os
import ssl
import urllib.request


def normalize_mapping(value):
    """Normalize only observed, equivalent OpenSearch mapping serialization."""
    if isinstance(value, list):
        return [normalize_mapping(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: normalize_mapping(item) for key, item in value.items()}
    if result.get('dynamic') == 'false':
        result['dynamic'] = False
    # OpenSearch omits explicit index:true, the default for these field types.
    if result.get('type') in ('text', 'keyword') and result.get('index') is True:
        del result['index']
    return result


def main():
    with open('/run/secrets/tripwire.json') as stream:
        secret = json.load(stream)
    base = os.environ.get('OPENSEARCH_URL', 'https://opensearch:9200')
    auth = base64.b64encode(('admin:' + secret['opensearch_password']).encode()).decode()

    def get(path, body=None):
        request = urllib.request.Request(base + path,
                                        data=json.dumps(body).encode() if body is not None else None,
                                        headers={'Authorization': 'Basic ' + auth,
                                                 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=25) as response:
            return json.load(response)

    alias = get('/_alias/tripwire-fakevm')
    writers = [name for name, item in alias.items()
               if item['aliases']['tripwire-fakevm'].get('is_write_index')]
    assert len(writers) == 1, 'fakevm alias must have exactly one write index'
    mapping = get('/' + writers[0] + '/_mapping')[writers[0]]['mappings']
    # OpenSearch returns the live setting as "false", while the template
    # retains JSON false. Both disable dynamic fields; never accept "true".
    assert mapping['dynamic'] is False or mapping['dynamic'] == 'false', 'fakevm mapping must be closed'
    fields = mapping['properties']['fakevm']['properties']
    for name in ('session', 'status', 'user', 'password', 'client'):
        assert fields[name]['type'] == 'keyword', name
    for name in ('command', 'output'):
        assert fields[name]['type'] == 'text', name
    assert mapping['properties']['source']['properties']['port']['type'] == 'integer'
    template = get('/_index_template/tripwire-fakevm')['index_templates'][0]['index_template']
    assert normalize_mapping(template['template']['mappings']) == normalize_mapping(mapping), 'template/live mapping mismatch'
    role = get('/_plugins/_security/api/roles/sentinel-writer')['sentinel-writer']
    assert any('tripwire-fakevm*' in p['index_patterns'] for p in role['index_permissions'])
    policy = get('/_plugins/_ism/policies/tripwire-fakevm')['policy']
    assert any(s['name'] == 'delete' for s in policy['states'])
    health = get('/_cluster/health/tripwire-fakevm*')
    assert health['status'] in ('green', 'yellow'), 'fakevm primary shards unavailable'
    pipeline = get('/_ingest/pipeline/tripwire-enrich')['tripwire-enrich']
    assert pipeline['processors'], 'enrichment pipeline is missing its processors'
    monitors = get('/_plugins/_alerting/monitors/_search', {
        'size': 100, 'query': {'match_phrase': {'monitor.name': 'tripwire-bait-used'}}})
    assert any(hit['_source']['name'] == 'tripwire-bait-used' and hit['_source']['enabled']
               for hit in monitors['hits']['hits']), 'bait-used monitor missing or disabled'
    print('PASS fakevm write alias, closed live/template mappings, writer role, retention policy and primary shards')
    print('PASS bait-used monitor enabled')
    print(json.dumps({'fakevm_events': get('/tripwire-fakevm/_count')['count']}))


if __name__ == '__main__':
    main()
