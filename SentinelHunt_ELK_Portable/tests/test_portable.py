import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import manage
import ship

class PortableChecks(unittest.TestCase):
    def setUp(self):
        test_root=ROOT/'work-tests'
        test_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=test_root)
        self.root = Path(self.temporary.name)
        self.previous = manage.RUNTIME
        manage.RUNTIME = self.root/'runtime'
        manage.init()
    def tearDown(self):
        manage.RUNTIME = self.previous
        self.temporary.cleanup()
    def test_initialization_preserves_existing_credentials_and_keys(self):
        original = {path.name:path.read_bytes() for path in manage.RUNTIME.glob('*.env')}
        manage.init()
        self.assertEqual(original,{path.name:path.read_bytes() for path in manage.RUNTIME.glob('*.env')})
        self.assertNotEqual(manage.read_env('agent1.env')['ES_PASSWORD'], manage.read_env('agent2.env')['ES_PASSWORD'])
    def test_publish_preserves_duplicate_raw_lines_with_distinct_ids(self):
        rows = [{'record_id':str(n),'capture_id':'same-session','raw_line':'same repeated line'} for n in (1,2)]
        path = manage.publish(rows)
        self.assertEqual([json.loads(line) for line in path.read_text().splitlines()],rows)
        self.assertFalse(list(path.parent.glob('*.tmp')))
    def test_label_or_reference_fields_do_not_reach_staging(self):
        with self.assertRaises(ValueError):
            manage.publish([{'raw_line':'text','scenario_label':'suspicious'}])
        self.assertFalse(list((manage.RUNTIME/'inbox').glob('*.ndjson')))
    def test_dataset_zip_imports_only_inputs(self):
        data=b'{"record_id":"r1","capture_id":"c1","raw_line":"actual text"}\n'
        path=self.root/'dataset.zip'
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('inputs.ndjson',data)
            archive.writestr('labels.ndjson','DO NOT IMPORT')
            archive.writestr('parsing-reference.ndjson','DO NOT IMPORT')
            archive.writestr('manifest.json',json.dumps({'file_sha256':{'inputs.ndjson':hashlib.sha256(data).hexdigest()}}))
        manage.stage_zip(path)
        files=list((manage.RUNTIME/'inbox').glob('*.ndjson'))
        self.assertEqual(len(files),1)
        self.assertEqual(json.loads(files[0].read_text())['raw_line'],'actual text')
    def test_corrupted_dataset_is_rejected_before_publication(self):
        path=self.root/'bad.zip'
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('inputs.ndjson','changed')
            archive.writestr('manifest.json',json.dumps({'file_sha256':{'inputs.ndjson':'0'*64}}))
        with self.assertRaises(ValueError):manage.stage_zip(path)
        self.assertFalse(list((manage.RUNTIME/'inbox').glob('*.ndjson')))
    def test_all_services_are_pinned_and_ports_are_loopback_only(self):
        compose=json.loads((ROOT/'compose.yaml').read_text())
        self.assertEqual(compose['name'],'se6014-sentinelhunt-portable')
        for service in compose['services'].values():
            self.assertTrue(service['image'].endswith(':8.19.23'))
            for port in service.get('ports',[]):self.assertTrue(port.startswith('127.0.0.1:'))
        self.assertEqual(compose['services']['elasticsearch']['environment']['xpack.security.enabled'],'true')
        self.assertNotIn('container_name',compose['services']['elasticsearch'])
    def test_role_boundaries_are_explicit(self):
        calls=[]
        def fake_es(method,path,body=None,who='elastic'):
            calls.append((method,path,body))
            if '/_security/service/' in path:return {'token':{'value':'FAKE_TEST_TOKEN_NOT_A_SECRET'}}
            return {}
        with patch.object(manage,'ensure_index'),patch.object(manage,'es',side_effect=fake_es):manage.provision()
        roles={path.rsplit('/',1)[-1]:body for _,path,body in calls if '/_security/role/' in path}
        hunter=roles['portable_agent2_hunter']['indices']
        self.assertEqual(hunter,[{'names':[manage.HUNT],'privileges':['read','view_index_metadata']}])
        parser=roles['portable_agent1_parser']['indices']
        self.assertNotIn('write',parser[0]['privileges'])
        self.assertEqual(parser[1]['names'],[manage.HUNT,manage.REGISTRY])
        self.assertNotIn('manage_index_templates',roles['portable_agent1_parser']['cluster'])
    def test_explicit_feed_survives_staging(self):
        row={'record_id':'feed-record','capture_id':'session','raw_line':'raw text','feed_name':'ubuntu-auth'}
        output=manage.publish([row])
        self.assertEqual(json.loads(output.read_text())['feed_name'],'ubuntu-auth')
        self.assertIn('feed_name',manage.RAW_PROPERTIES)
        self.assertIn('feed_name',manage.HUNT_PROPERTIES)
    def test_invalid_feed_is_rejected(self):
        with self.assertRaises(ValueError):manage.publish([{'raw_line':'text','feed_name':'bad feed\nvalue'}])
        self.assertFalse(list((manage.RUNTIME/'inbox').glob('*.ndjson')))
    def test_endpoint_identity_and_grouping_include_feed(self):
        a=ship.envelope('same','host','offset:1','ubuntu-auth')
        b=ship.envelope('same','host','offset:1','nginx-access')
        self.assertNotEqual(a['record_id'],b['record_id'])
        self.assertEqual(a['feed_name'],'ubuntu-auth')
    def test_kibana_token_request_has_no_body(self):
        calls=[]
        def fake_es(method,path,body=None,who='elastic'):
            calls.append((method,path,body))
            if '/_security/service/' in path:return {'token':{'value':'FAKE_TEST_TOKEN'}}
            return {}
        with patch.object(manage,'ensure_index'),patch.object(manage,'es',side_effect=fake_es):manage.provision()
        token_calls=[call for call in calls if '/_security/service/' in call[1]]
        self.assertEqual(len(token_calls),1)
        self.assertIsNone(token_calls[0][2])
        roles={path.rsplit('/',1)[-1]:body for _,path,body in calls if '/_security/role/' in path}
        self.assertIn('manage_ingest_pipelines',roles['portable_agent1_parser']['cluster'])
        self.assertNotIn('manage_ingest_pipelines',roles['portable_agent2_hunter']['cluster'])
    def test_endpoint_record_identity_distinguishes_file_positions(self):
        a=ship.envelope('same','source','file:0')
        b=ship.envelope('same','source','file:20')
        self.assertNotEqual(a['record_id'],b['record_id'])
        self.assertEqual(a,ship.envelope('same','source','file:0'))

if __name__=='__main__':unittest.main(verbosity=2)
