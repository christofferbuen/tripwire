"""Verify one operator-created interactive SSH session in live OpenSearch.

Run inside the collector enricher with --session UUID --since UTC_TIMESTAMP.
Only bounded, exact-session reads are issued. Captured content is never printed.
The smoke client must send whoami, pwd, id, then exit in one interactive shell.
"""
import argparse
import base64
from datetime import datetime
import json
import os
import ssl
import urllib.error
import urllib.request
import uuid

EXPECTED = {
    'whoami': 'deploy',
    'pwd': '/home/deploy',
    'id': 'uid=1001(deploy) gid=1001(deploy) groups=1001(deploy)',
}


def verify(result, session, since):
    if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
        raise ValueError('search timed out or a shard failed')
    hits = result['hits']
    total = hits['total']
    if total['relation'] != 'eq' or total['value'] != len(hits['hits']):
        raise ValueError('session result is incomplete')
    events = [hit['_source'] for hit in hits['hits']]
    if not events:
        raise ValueError('session has not reached OpenSearch')
    found = set()
    statuses = []
    for event in events:
        fake = event['fakevm']
        if fake['session'] != session or event['event']['module'] != 'fakevm':
            raise ValueError('unexpected session or producer')
        stamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp < since:
            raise ValueError('event predates the smoke test')
        status = fake['status']
        statuses.append(status)
        if status == 'start':
            if fake.get('user') != 'deploy' or not event.get('source', {}).get('ip'):
                raise ValueError('session start is missing username or address')
        if status == 'interaction':
            command = fake.get('command', '')
            if command not in EXPECTED:
                raise ValueError('unexpected command in isolated smoke session')
            if fake.get('output', '').strip() != EXPECTED[command]:
                raise ValueError('stored static command output does not match')
            found.add(command)
    if statuses.count('start') != 1 or statuses.count('end') != 1:
        raise ValueError('expected one start and one end event')
    if found != set(EXPECTED) or statuses.count('interaction') != len(EXPECTED):
        raise ValueError('missing or duplicated smoke command events')
    if len(events) != 5:
        raise ValueError('unexpected additional session events')
    return {'session_events': len(events), 'verified_commands': len(found),
            'start_present': True, 'end_present': True}


def selftest():
    import copy
    session = str(uuid.uuid4())
    since = datetime.fromisoformat('2026-01-01T00:00:00+00:00')
    events = []
    for status, command in [('start', ''), *[('interaction', c) for c in EXPECTED], ('end', '')]:
        event = {'@timestamp': since.isoformat(), 'event': {'module': 'fakevm'},
                 'fakevm': {'session': session, 'status': status, 'user': 'deploy',
                            'command': command, 'output': EXPECTED.get(command, '')}}
        if status != 'end':
            event['source'] = {'ip': '192.0.2.1'}
        events.append({'_source': event})
    result = {'hits': {'total': {'relation': 'eq', 'value': 5}, 'hits': events}}
    assert verify(result, session, since)['verified_commands'] == 3
    failures = []
    missing = copy.deepcopy(result)
    missing['hits']['hits'].pop()
    missing['hits']['total']['value'] = 4
    failures.append(missing)
    wrong = copy.deepcopy(result)
    wrong['hits']['hits'][1]['_source']['fakevm']['output'] = 'incorrect'
    failures.append(wrong)
    foreign = copy.deepcopy(result)
    foreign['hits']['hits'][1]['_source']['fakevm']['session'] = str(uuid.uuid4())
    failures.append(foreign)
    partial = copy.deepcopy(result)
    partial['hits']['total']['relation'] = 'gte'
    failures.append(partial)
    failed_shard = copy.deepcopy(result)
    failed_shard['_shards'] = {'failed': 1}
    failures.append(failed_shard)
    for bad in failures:
        try:
            verify(bad, session, since)
        except ValueError:
            continue
        raise AssertionError('invalid session accepted')
    print('PASS complete session including address-free end; missing, corrupt, mixed and partial results rejected')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--session', type=uuid.UUID)
    parser.add_argument('--since')
    parser.add_argument('--selftest', action='store_true')
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    if not args.session or not args.since:
        parser.error('--session and --since are required')
    since = datetime.fromisoformat(args.since.replace('Z', '+00:00'))
    if since.tzinfo is None:
        parser.error('--since requires a timezone')
    with open('/run/secrets/tripwire.json') as stream:
        secret = json.load(stream)
    auth = base64.b64encode(('admin:' + secret['opensearch_password']).encode()).decode()
    body = {'size': 20, 'track_total_hits': True,
            '_source': ['@timestamp', 'event.module', 'source.ip', 'fakevm.session',
                        'fakevm.status', 'fakevm.user', 'fakevm.command', 'fakevm.output'],
            'query': {'bool': {'filter': [
                {'term': {'fakevm.session': str(args.session)}},
                {'range': {'@timestamp': {'gte': since.isoformat()}}}]}},
            'sort': [{'@timestamp': 'asc'}]}
    base = os.environ.get('OPENSEARCH_URL', 'https://opensearch:9200')
    request = urllib.request.Request(base + '/tripwire-fakevm-*/_search',
                                     data=json.dumps(body).encode(),
                                     headers={'Authorization': 'Basic ' + auth,
                                              'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=25) as response:
            result = json.load(response)
        print(json.dumps(verify(result, str(args.session), since)))
    except urllib.error.HTTPError as exc:
        raise SystemExit('OpenSearch HTTP status ' + str(exc.code)) from None
    except (ValueError, KeyError) as exc:
        # Do not interpolate stored values, response bodies or credentials.
        raise SystemExit('Session verification failed; inspect the private test on the host') from None


if __name__ == '__main__':
    main()
