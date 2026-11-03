"""Real Foundation archive round trips, isolated from system LuLu and Claude."""
import importlib.util
import json
import os
import plistlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('staging_build', ROOT / 'tools/build_lulu_staging_cli.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)

FIXTURE_SWIFT = r'''
import Foundation
@objc(Rule) class Rule: NSObject, NSSecureCoding {
 static var supportsSecureCoding: Bool {true}
 var values: [String:Any] = [:]
 override init(){super.init();values=["key":"/fixture/*","uuid":"existing-uuid","path":"/fixture/*","name":"Existing","endpointAddr":"192.0.2.0/24","endpointPort":"443","isEndpointAddrRegex":NSNumber(value:2),"type":NSNumber(value:3),"scope":NSNumber(value:1),"action":NSNumber(value:0)]}
 required init?(coder:NSCoder){super.init();for k in ["key","uuid","path","name","endpointAddr","endpointPort","endpointHost"]{if let v=coder.decodeObject(of:NSString.self,forKey:k){values[k]=v}};for k in ["type","scope","action","isEndpointAddrRegex","isDisabled","pid"]{if let v=coder.decodeObject(of:NSNumber.self,forKey:k){values[k]=v}};for k in ["creation","expiration"]{_ = coder.decodeObject(of:NSDate.self,forKey:k)};_ = coder.decodeObject(of:[NSDictionary.self,NSArray.self,NSString.self,NSNumber.self],forKey:"csInfo")}
 func encode(with coder:NSCoder){for k in ["key","uuid","path","name","endpointAddr","endpointPort","endpointHost","isEndpointAddrRegex","type","scope","action","isDisabled","pid","csInfo","creation","expiration"]{coder.encode(values[k],forKey:k)}}
}
let url=URL(fileURLWithPath:CommandLine.arguments[2])
if CommandLine.arguments[1]=="create" {
 let fixture:[String:Any] = ["/fixture/*":["rules":[Rule()],"extra-metadata":"preserve-this"],"unrelated":["rules":[],"extra-metadata":"also-preserve"]]
 try NSKeyedArchiver.archivedData(withRootObject:fixture,requiringSecureCoding:true).write(to:url)
} else {
 let classes:[AnyClass]=[NSDictionary.self,NSMutableDictionary.self,NSArray.self,NSMutableArray.self,NSString.self,NSNumber.self,NSMutableSet.self,NSDate.self,Rule.self]
 let dict=try NSKeyedUnarchiver.unarchivedObject(ofClasses:classes,from:Data(contentsOf:url)) as! [String:[String:Any]]
 var result:[String:Any]=[:]
 for (key,entry) in dict {result[key] = ["rules":(entry["rules"] as? [Rule] ?? []).map{$0.values},"extra-metadata":entry["extra-metadata"] ?? ""]}
 let data=try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys]);print(String(data:data,encoding:.utf8)!)
}
'''

class StagingCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='guard-lulu-codec-tests-')
        cls.path = Path(cls.temp.name)
        cls.cli = builder.build(cls.path / 'staging-cli')
        source = cls.path / 'fixture.swift';source.write_text(FIXTURE_SWIFT)
        cls.fixture_tool = cls.path / 'fixture'
        subprocess.run(['/usr/bin/xcrun','swiftc','-module-cache-path',str(cls.path/'ModuleCache'),str(source),'-o',str(cls.fixture_tool)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def setUp(self):
        self.file = self.path / 'staged-rules.plist'
        subprocess.run([str(self.fixture_tool),'create',str(self.file)],check=True)
        self.env = dict(os.environ,GUARD_STAGING_RULES=str(self.file))

    def run_cli(self,*args,env=None):
        return subprocess.run([str(self.cli),*args],env=env or self.env,capture_output=True,text=True,timeout=5)

    def read(self):
        return json.loads(subprocess.check_output([str(self.fixture_tool),'read',str(self.file)],text=True))

    def test_new_lulu_nsnumber_enum_archive_is_readable(self):
        result=self.run_cli('list');self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('existing-uuid',result.stdout)

    def test_add_preserves_existing_enum_metadata_and_unrelated_entries(self):
        before=self.read()
        result=self.run_cli('add','--key','/guard-fixture/*','--path','/guard-fixture/*','--action','block')
        self.assertEqual(result.returncode,0,result.stderr)
        after=self.read()
        self.assertEqual(before['/fixture/*'],after['/fixture/*'])
        self.assertEqual(before['unrelated'],after['unrelated'])
        self.assertEqual(after['/fixture/*']['rules'][0]['isEndpointAddrRegex'],2)
        self.assertEqual(after['/guard-fixture/*']['rules'][0]['action'],0)

    def test_reload_is_unconditionally_unavailable(self):
        result=self.run_cli('reload');self.assertEqual(result.returncode,64)
        self.assertIn('deliberately unavailable',result.stderr)

    def test_unknown_future_rule_fields_refuse_write_without_data_loss(self):
        archive=plistlib.loads(self.file.read_bytes())
        for obj in archive['$objects']:
            if isinstance(obj,dict) and 'uuid' in obj and 'endpointAddr' in obj:
                obj['futureSecurityField']=True
        self.file.write_bytes(plistlib.dumps(archive,fmt=plistlib.FMT_BINARY))
        before=self.file.read_bytes()
        result=self.run_cli('add','--key','/new/*','--path','/new/*','--action','block')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Unknown Rule schema',result.stderr)
        self.assertEqual(self.file.read_bytes(),before)

    def test_missing_staging_path_cannot_touch_default_system_rules(self):
        env=dict(os.environ);env.pop('GUARD_STAGING_RULES',None)
        result=self.run_cli('list',env=env);self.assertEqual(result.returncode,64)

    def test_system_rules_path_rejected(self):
        env=dict(self.env,GUARD_STAGING_RULES='/Library/Objective-See/LuLu/rules.plist')
        result=self.run_cli('add','--key','x','--path','x','--action','block',env=env)
        self.assertEqual(result.returncode,64)

    def test_symlink_escape_rejected(self):
        link=self.path/'escape';link.symlink_to('/Library',target_is_directory=True)
        try:
            result=self.run_cli('list',env=dict(self.env,GUARD_STAGING_RULES=str(link/'staged-rules.plist')))
            self.assertEqual(result.returncode,64)
        finally:link.unlink()

if __name__ == '__main__':unittest.main(verbosity=2)
