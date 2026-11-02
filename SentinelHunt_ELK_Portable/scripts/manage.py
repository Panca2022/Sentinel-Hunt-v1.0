#!/usr/bin/env python3
"""Local Linux/WSL setup and verification. Python standard library only."""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'
PROJECT = 'se6014-sentinelhunt-portable'
ES_URL = 'https://localhost:19200'
PORTS = (19200, 15601, 18088, 15514)
RAW = 'sentinelhunt-raw-v1'
HUNT = 'sentinelhunt-hunt-v1'
REGISTRY = 'sentinelhunt-schema-v1'
REJECTED = 'sentinelhunt-rejected-v1'

def read_env(name):
    return dict(line.split('=', 1) for line in (RUNTIME/name).read_text().splitlines()
                if line and not line.startswith('#'))

def write_env(name, values):
    path = RUNTIME/name
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        for key, value in values.items():
            output.write(f'{key}={value}\n')
    temporary.chmod(0o600)
    temporary.replace(path)

def init():
    os.umask(0o077)
    RUNTIME.mkdir(exist_ok=True)
    RUNTIME.chmod(0o700)
    (RUNTIME/'inbox').mkdir(exist_ok=True)
    (RUNTIME/'inbox').chmod(0o755)
    defaults = {
        'elasticsearch.env': {'ELASTIC_PASSWORD': secrets.token_hex(24)},
        'kibana.env': {name: secrets.token_hex(32) for name in (
            'XPACK_SECURITY_ENCRYPTIONKEY', 'XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY',
            'XPACK_REPORTING_ENCRYPTIONKEY')},
        'logstash.env': {'LOGSTASH_USER': 'portable_logstash', 'LOGSTASH_PASSWORD': secrets.token_hex(24),
                         'PUSH_USER': 'portable_endpoint', 'PUSH_PASSWORD': secrets.token_hex(24)},
        'agent1.env': {'ES_USERNAME': 'portable_agent1', 'ES_PASSWORD': secrets.token_hex(24)},
        'agent2.env': {'ES_USERNAME': 'portable_agent2', 'ES_PASSWORD': secrets.token_hex(24)},
    }
    for name, values in defaults.items():
        if not (RUNTIME/name).exists():
            write_env(name, values)
    print('Local secrets initialized; existing credentials preserved.')

def compose(*args, capture=False):
    result = subprocess.run(['docker', 'compose', '-p', PROJECT, '-f', str(ROOT/'compose.yaml'), *args],
                            cwd=ROOT, check=True, text=True, capture_output=capture)
    return result.stdout if capture else None

def preflight():
    if sys.platform != 'linux':
        raise RuntimeError('Run inside Ubuntu/WSL, not Windows PowerShell.')
    if not shutil.which('docker'):
        raise RuntimeError('Docker CLI is missing in this Ubuntu environment.')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['docker', 'compose', 'version'], check=True)
    value = int(Path('/proc/sys/vm/max_map_count').read_text())
    if value < 1048576:
        raise RuntimeError('Run sudo sysctl -w vm.max_map_count=1048576, then retry. This is a host-wide runtime setting.')
    if shutil.disk_usage(ROOT).free < 8 * 1024**3:
        raise RuntimeError('Need at least 8 GiB free disk for images and lab data.')
    if not compose('ps', '-aq', capture=True).strip():
        for port in PORTS:
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', port))
                except OSError as error:
                    raise RuntimeError(f'Port {port} is occupied; preserve that service and resolve the conflict first.') from error
    compose('config', '--quiet')
    print('PASS: Docker, Compose, kernel setting, disk, and initial ports checked.')

def credentials(who):
    if who == 'elastic':
        return ('elastic', read_env('elasticsearch.env')['ELASTIC_PASSWORD'])
    values = read_env(who+'.env')
    return values['ES_USERNAME'], values['ES_PASSWORD']

def es(method, endpoint, body=None, who='elastic'):
    username, password = credentials(who)
    context = ssl.create_default_context(cafile=str(RUNTIME/'ca.crt'))
    request = urllib.request.Request(ES_URL+endpoint,
        data=None if body is None else json.dumps(body).encode(), method=method,
        headers={'Content-Type': 'application/json', 'Authorization': 'Basic '+
                 base64.b64encode(f'{username}:{password}'.encode()).decode()})
    with urllib.request.urlopen(request, context=context, timeout=45) as response:
        return json.load(response)

def ensure_index(name, properties, dynamic=True):
    try:
        es('GET', '/'+name)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        es('PUT', '/'+name, {'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
                             'mappings': {'dynamic': dynamic, 'properties': properties}})

RAW_PROPERTIES = {
    '@timestamp': {'type': 'date'}, 'received_at': {'type': 'date'},
    'record_id': {'type': 'keyword'}, 'capture_id': {'type': 'keyword'},
    'raw_line': {'type': 'text'}, 'source_name': {'type': 'keyword'},
    'ingestion_channel': {'type': 'keyword'}, 'feed_name': {'type': 'keyword'},
}
HUNT_PROPERTIES = {
    '@timestamp': {'type': 'date'}, 'record_id': {'type': 'keyword'},
    'capture_id': {'type': 'keyword'}, 'feed_name': {'type': 'keyword'}, 'raw_line': {'type': 'text'}, 'message': {'type': 'text'},
    'event': {'properties': {'original': {'type': 'text'}, 'action': {'type': 'keyword'}, 'outcome': {'type': 'keyword'}}},
    'source': {'properties': {'ip': {'type': 'ip'}, 'port': {'type': 'integer'}}},
    'destination': {'properties': {'ip': {'type': 'ip'}, 'port': {'type': 'integer'}}},
    'user': {'properties': {'name': {'type': 'keyword'}, 'target': {'properties': {'name': {'type': 'keyword'}}}}},
    'host': {'properties': {'name': {'type': 'keyword'}}},
    'log': {'properties': {'category': {'type': 'keyword'}}},
    'process': {'properties': {'name': {'type': 'keyword'}, 'pid': {'type': 'long'},
                              'command_line': {'type': 'keyword'}, 'working_directory': {'type': 'keyword'}}},
    'terminal': {'type': 'keyword'},
    'network': {'properties': {'transport': {'type': 'keyword'}, 'bytes': {'type': 'long'}}},
    'rule': {'properties': {'name': {'type': 'keyword'}}},
    'http': {'properties': {'version': {'type': 'keyword'},
              'request': {'properties': {'method': {'type': 'keyword'}, 'referrer': {'type': 'keyword'}}},
              'response': {'properties': {'status_code': {'type': 'integer'}, 'body': {'properties': {'bytes': {'type': 'long'}}}}}}},
    'url': {'properties': {'original': {'type': 'keyword'}}},
    'user_agent': {'properties': {'original': {'type': 'keyword'}}},
}

def provision():
    ensure_index(RAW, RAW_PROPERTIES, 'strict')
    ensure_index(REJECTED, {key: RAW_PROPERTIES[key] for key in ('@timestamp','received_at','record_id','ingestion_channel','feed_name')} |
                 {'rejection_reason': {'type': 'keyword'}}, 'strict')
    ensure_index(HUNT, HUNT_PROPERTIES, 'strict')
    ensure_index(REGISTRY, {})
    for index in (RAW, HUNT, REJECTED):
        es('PUT', '/'+index+'/_mapping', {'properties': {'feed_name': {'type': 'keyword'}}})
    roles = {
        'portable_logstash_writer': {'cluster': ['monitor'], 'indices': [
            {'names': [RAW, REJECTED], 'privileges': ['write']}]},
        'portable_agent1_parser': {'cluster': ['monitor', 'manage_ingest_pipelines'], 'indices': [
            {'names': [RAW], 'privileges': ['read','view_index_metadata']},
            {'names': [HUNT, REGISTRY], 'privileges': ['read','write','view_index_metadata']}]},
        'portable_agent2_hunter': {'cluster': ['monitor'], 'indices': [
            {'names': [HUNT], 'privileges': ['read','view_index_metadata']}]},
    }
    for name, role in roles.items():
        es('PUT', '/_security/role/'+name, role)
    logstash = read_env('logstash.env')
    users = [('portable_logstash', logstash['LOGSTASH_PASSWORD'], 'portable_logstash_writer')]
    for agent in ('agent1','agent2'):
        username, password = credentials(agent)
        users.append((username, password, 'portable_agent1_parser' if agent == 'agent1' else 'portable_agent2_hunter'))
    for username, password, role in users:
        es('PUT', '/_security/user/'+username, {'password': password, 'roles': [role]})
    kibana = read_env('kibana.env')
    if 'ELASTICSEARCH_SERVICEACCOUNTTOKEN' not in kibana:
        result = es('POST', '/_security/service/elastic/kibana/credential/token')
        kibana['ELASTICSEARCH_SERVICEACCOUNTTOKEN'] = result['token']['value']
        write_env('kibana.env', kibana)
    print('PASS: staging/hunt/schema indices and restricted accounts ready.')

def start():
    init()
    preflight()
    compose('pull')
    compose('run', '--rm', '--no-deps', 'setup')
    compose('up', '-d', '--no-deps', '--wait', '--wait-timeout', '360', 'elasticsearch')
    compose('cp', 'elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt', str(RUNTIME/'ca.crt'))
    (RUNTIME/'ca.crt').chmod(0o644)
    provision()
    # Check Logstash configuration in the image before starting its pipeline.
    compose('run', '--rm', '--no-deps', 'logstash', 'bin/logstash', '--config.test_and_exit')
    compose('up', '-d', '--no-deps', '--wait', '--wait-timeout', '600', 'kibana', 'logstash')
    verify()

def verify():
    username, _ = credentials('agent1')
    assert es('GET', '/_security/_authenticate', who='agent1')['username'] == username
    expected = {
        'agent1': [(RAW, 'read', True), (RAW, 'write', False), (HUNT,'write',True)],
        'agent2': [(HUNT, 'read', True), (HUNT,'write',False), (RAW,'read',False)],
    }
    for agent, checks in expected.items():
        for index, privilege, allowed in checks:
            result = es('POST', '/_security/user/_has_privileges', {
                'index': [{'names': [index], 'privileges': [privilege]}]}, agent)
            assert result['has_all_requested'] == allowed, (agent,index,privilege)
    try:
        urllib.request.urlopen(ES_URL, context=ssl.create_default_context(cafile=str(RUNTIME/'ca.crt')), timeout=15)
    except urllib.error.HTTPError as error:
        assert error.code == 401
    else:
        raise AssertionError('Unauthenticated Elasticsearch request was accepted')
    with urllib.request.urlopen('http://127.0.0.1:15601/api/status', timeout=15) as response:
        assert response.status == 200
    assert es('GET', '/_cluster/health')['status'] in ('green', 'yellow')
    print('PASS: HTTPS/authentication, Kibana readiness, and Agent 1/2 access boundaries verified.')
    print('Kibana: http://localhost:15601 | Elasticsearch: https://localhost:19200')

def validate_feed(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) is None:
        raise ValueError('feed_name must contain 1-128 letters, digits, dots, underscores, colons or hyphens')
    return value

def publish(rows, filename=None):
    path = RUNTIME/'inbox'/(filename or ('batch-'+uuid.uuid4().hex+'.ndjson'))
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        for row in rows:
            if set(row) - {'record_id','capture_id','raw_line','source_name','feed_name'}:
                raise ValueError('Input contains unexpected fields')
            if not isinstance(row.get('raw_line'), str) or not row['raw_line']:
                raise ValueError('Input requires a nonempty raw_line')
            if row.get('feed_name') is not None:
                validate_feed(row['feed_name'])
            output.write(json.dumps(row)+'\n')
    temporary.chmod(0o644)
    temporary.replace(path)
    return path

def push(row):
    values = read_env('logstash.env')
    token = base64.b64encode((values['PUSH_USER']+':'+values['PUSH_PASSWORD']).encode()).decode()
    request = urllib.request.Request('http://127.0.0.1:18088', data=json.dumps(row).encode(),
        headers={'Content-Type':'application/json','Authorization':'Basic '+token}, method='POST')
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200

def smoke():
    marker = 'portable-smoke-'+uuid.uuid4().hex
    pull = {'record_id': marker+'-pull','capture_id':marker,'source_name':'portable-smoke',
            'raw_line': marker+' pull test', 'feed_name': 'smoke-auth'}
    pushed = dict(pull, record_id=marker+'-push', raw_line=marker+' push test', feed_name='smoke-web')
    publish([pull])
    push(pushed)
    with socket.create_connection(('127.0.0.1',15514), timeout=10) as stream:
        for number in (1,2):
            stream.sendall(f'<14>Oct 23 12:00:00 demo-host demo: {marker} stream {number}\n'.encode())
            time.sleep(0.25)
    query = {'size':10,'query':{'match_phrase':{'raw_line':marker}}}
    deadline = time.monotonic()+120
    while time.monotonic() < deadline:
        result = es('POST','/'+RAW+'/_search',query)
        hits = result['hits']['hits']
        if len(hits) == 4:
            break
        time.sleep(2)
    else:
        raise RuntimeError('Expected four staging records; inspect compose logs before retrying.')
    channels = [hit['_source']['ingestion_channel'] for hit in hits]
    assert sorted(channels) == ['pull','push','stream','stream'], channels
    assert {hit['_source']['feed_name'] for hit in hits} == {'smoke-auth','smoke-web','local-syslog'}
    assert {hit['_id'] for hit in hits} == {hit['_source']['record_id'] for hit in hits}
    evidence = {'run_id':marker,'channels':channels,'raw_ids':[hit['_id'] for hit in hits],
                'agent1_executed':False,'hunt_index_populated_by_test':False}
    (RUNTIME/('smoke-'+marker+'.json')).write_text(json.dumps(evidence,indent=2)+'\n')
    print('PASS: folder pickup=1, authenticated push=1, continuous stream=2 in raw staging.')
    print('These are ingestion checks, not an Agent 1/2 end-to-end demonstration.')

def stage_zip(path, feed_name=None):
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        data = archive.read('inputs.ndjson')
        expected = manifest['file_sha256']['inputs.ndjson']
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Dataset inputs checksum mismatch')
        rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
    if feed_name is not None:
        validate_feed(feed_name)
        rows = [dict(row, feed_name=feed_name) for row in rows]
    print(f'Published {len(rows)} raw inputs: {publish(rows)}')
    print('No labels or parsing references imported. Agent 1 must process staging next.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init','check','start','verify','smoke','status','stop','stage','password'])
    parser.add_argument('value', nargs='?')
    parser.add_argument('--feed', help='Stable source/feed name for dataset staging')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.action == 'init': init()
    elif args.action == 'check': init(); preflight()
    elif args.action == 'start': start()
    elif args.action == 'verify': verify()
    elif args.action == 'smoke': smoke()
    elif args.action == 'status': compose('ps','-a')
    elif args.action == 'stop': compose('stop')
    elif args.action == 'stage':
        if not args.value: parser.error('stage needs the dataset ZIP path')
        stage_zip(args.value, args.feed)
    elif args.action == 'password':
        if args.value not in ('elastic','agent1','agent2'): parser.error('choose elastic, agent1, or agent2')
        print(credentials(args.value)[1])

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, AssertionError, subprocess.CalledProcessError) as error:
        print(f'STOP: {error}', file=sys.stderr)
        sys.exit(1)
