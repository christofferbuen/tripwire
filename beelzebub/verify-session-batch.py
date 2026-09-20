"""Run in the collector enricher; stdin is the operator's smoke-session result.

Only exact synthetic session IDs are queried. Prints counts, never captured text.
"""
import base64
from collections import Counter
import json
import os
import ssl
import sys
import urllib.request
import uuid

def main():
    manifest=json.load(sys.stdin)
    assert manifest['passed'] and 1<=len(manifest['sessions'])<=10
    secret=json.load(open('/run/secrets/tripwire.json'))
    auth=base64.b64encode(('admin:'+secret['opensearch_password']).encode()).decode()
    base=os.environ.get('OPENSEARCH_URL','https://opensearch:9200')
    total=0
    for session in manifest['sessions']:
        sid=str(uuid.UUID(session['session']))
        body={'size':100,'track_total_hits':True,'query':{'term':{'fakevm.session':sid}},
              '_source':['fakevm.session','fakevm.status','fakevm.command','fakevm.output','source.ip','event.module']}
        request=urllib.request.Request(base+'/tripwire-fakevm-*/_search',data=json.dumps(body).encode(),
            headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        with urllib.request.urlopen(request,context=ssl._create_unverified_context(),timeout=25) as response:result=json.load(response)
        assert not result.get('timed_out') and not result['_shards']['failed']
        hits=result['hits'];assert hits['total']=={'value':session['events'],'relation':'eq'}
        assert len(hits['hits'])==session['events']
        events=[hit['_source'] for hit in hits['hits']]
        assert all(e['fakevm']['session']==sid and e['event']['module']=='fakevm' for e in events)
        assert Counter(e['fakevm']['status'] for e in events)=={'start':1,'interaction':len(session['commands']),'end':1}
        assert all(e.get('source',{}).get('ip') for e in events if e['fakevm']['status']!='end')
        actual=Counter((e['fakevm'].get('command',''),e['fakevm'].get('output','').strip()) for e in events if e['fakevm']['status']=='interaction')
        assert actual==Counter(zip(session['commands'],session['outputs']))
        total+=len(events)
    print(json.dumps({'verified_sessions':len(manifest['sessions']),'verified_events':total,
                      'verified_command_output_pairs':sum(len(s['commands']) for s in manifest['sessions'])}))

if __name__=='__main__':main()
