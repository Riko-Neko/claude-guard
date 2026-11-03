"""Archive transforms verified against the real Foundation decoder."""
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
import os
import test_lulu_staging as fixtures
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('archive',ROOT/'src/lulu_archive.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the native fixture producer/reader, not a Python codec lookalike.
        fixtures.StagingCodecTests.setUpClass()
    @classmethod
    def tearDownClass(cls):fixtures.StagingCodecTests.tearDownClass()

    def fixture(self):
        path=fixtures.StagingCodecTests.path/'staged-rules.plist'
        subprocess.run([str(fixtures.StagingCodecTests.fixture_tool),'create',str(path)],check=True)
        return path

    def test_append_decodes_natively_and_preserves_every_existing_object(self):
        path=self.fixture();old=plistlib.loads(path.read_bytes())
        for obj in old['$objects']:
            if isinstance(obj,dict) and 'uuid' in obj:obj['futureSecurityField']={'keep':True}
        data=plistlib.dumps(old,fmt=plistlib.FMT_BINARY)
        result=a.make_policy(data,['/guard-fixture/*'],47831)
        after=plistlib.loads(result);root=old['$top']['root'].data
        for index,obj in enumerate(old['$objects']):
            if index!=root:self.assertEqual(obj,after['$objects'][index])
        path.write_bytes(result)
        native=json.loads(subprocess.check_output([str(fixtures.StagingCodecTests.fixture_tool),'read',str(path)],text=True))
        rules=native['/guard-fixture/*']['rules']
        self.assertEqual([(r['action'],r['endpointAddr'],r['endpointPort']) for r in rules],[(0,'*','*'),(1,'127.0.0.1','47831')])
        self.assertEqual(native['/fixture/*']['extra-metadata'],'preserve-this')
        self.assertEqual(native['unrelated']['extra-metadata'],'also-preserve')

    def test_existing_protected_scope_is_not_silently_replaced(self):
        path=self.fixture()
        with self.assertRaises(a.PolicyError):a.make_policy(path.read_bytes(),['/fixture/*'],47831)

    def test_invalid_ports_and_scopes_rejected(self):
        path=self.fixture()
        for paths,port in [(['/guard-fixture/*'],789),(['*'],47831),(['/x/../y/*'],47831)]:
            with self.subTest(paths=paths,port=port),self.assertRaises(a.PolicyError):a.make_policy(path.read_bytes(),paths,port)

    def test_client_install_replaces_only_client_policy_and_keeps_unrelated_entries(self):
        sp=importlib.util.spec_from_file_location('setup_archive_test',ROOT/'tools/lulu_setup.py')
        setup=importlib.util.module_from_spec(sp);sp.loader.exec_module(setup)
        path=self.fixture()
        initial=a.make_policy(path.read_bytes(),['/Applications/Claude.app/*'],47831)
        result,count=setup.candidate_rules(initial,'claude',os.getuid())
        path.write_bytes(result)
        native=json.loads(subprocess.check_output([str(fixtures.StagingCodecTests.fixture_tool),'read',str(path)],text=True))
        self.assertEqual(native['/fixture/*']['extra-metadata'],'preserve-this')
        self.assertEqual(native['unrelated']['extra-metadata'],'also-preserve')
        self.assertEqual(len(native['/Applications/Claude.app/*']['rules']),2)
        self.assertEqual(count,8)

if __name__=='__main__':unittest.main(verbosity=2)
