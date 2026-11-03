"""Replay the page-location failure without creating a window or web view."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class PageLocationTests(unittest.TestCase):
    def test_local_pages_never_receive_query_or_fragment_and_access_is_directory(self):
        with tempfile.TemporaryDirectory(prefix='guard-page-location-') as temp:
            folder=Path(temp)
            source=folder/'main.swift'
            source.write_text('''import Foundation
let resources=URL(fileURLWithPath:"/Applications/Claude Guard 測試.app/Contents/Resources",isDirectory:true)
let location=GuardPageLocation(resources:resources)
precondition(location.page.isFileURL && location.directory.isFileURL)
precondition(location.page.query == nil && location.page.fragment == nil)
precondition(location.directory.hasDirectoryPath)
precondition(location.page.deletingLastPathComponent().path == location.directory.path)
precondition(location.page.lastPathComponent == "index.html")
precondition(!GuardSetupPolicy.requiresFilterShutdown(currentMode:"proxy",configured:false,targetMode:"proxy"))
precondition(!GuardSetupPolicy.requiresFilterShutdown(currentMode:"enhanced",configured:false,targetMode:"proxy"))
precondition(GuardSetupPolicy.requiresFilterShutdown(currentMode:"enhanced",configured:true,targetMode:"proxy"))
precondition(!GuardSetupPolicy.requiresFilterShutdown(currentMode:"proxy",configured:true,targetMode:"proxy"))
precondition(!GuardSetupPolicy.requiresFilterShutdown(currentMode:"proxy",configured:true,targetMode:"enhanced"))
let environment=GuardChildEnvironment.make(["SUDO_UID":"0","SUDO_GID":"0","SUDO_USER":"root","PATH":"/fixture","SSH_AUTH_SOCK":"/fixture/agent"],language:"en")
precondition(environment["SUDO_UID"] == nil && environment["SUDO_USER"] == nil)
precondition(environment["PATH"] == "/fixture" && environment["SSH_AUTH_SOCK"] == "/fixture/agent")
precondition(GuardLifecyclePolicy.decision(setup:true,operation:false,backend:false,claude:false)=="cancelSetup")
precondition(GuardLifecyclePolicy.decision(setup:false,operation:false,backend:true,claude:false)=="endCheck")
precondition(GuardLifecyclePolicy.decision(setup:false,operation:false,backend:false,claude:false)=="continue")
precondition(GuardLifecyclePolicy.decision(setup:false,operation:false,backend:true,claude:true)=="claude")
precondition(GuardLifecyclePolicy.decision(setup:false,operation:true,backend:false,claude:false)=="operation")
''')
            built=subprocess.run(['/usr/bin/xcrun','swiftc','-module-cache-path',str(folder/'ModuleCache'),str(ROOT/'src/GuardInterface.swift'),str(source),'-framework','AppKit','-framework','WebKit','-o',str(folder/'url-test')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            result=subprocess.run([str(folder/'url-test')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
