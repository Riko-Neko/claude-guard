"""Measure isolated, never-shown AppKit notices; no AppDelegate or live apps."""
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CompactNoticeTests(unittest.TestCase):
    def test_compact_notice_fits_content_and_scrolls_long_diagnostics(self):
        code = r'''import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
func property<T>(_ object:Any,_ name:String,_ type:T.Type)->T {
 let value=Mirror(reflecting:object).children.first{$0.label==name}!.value
 return (Mirror(reflecting:value).children.first?.value as? T) ?? (value as! T)
}
let ui=GuardInterface()
var pending=false
ui.state={ ["approvalRequired":pending,"canApproveExit":true,"reputation":["checked_at":ISO8601DateFormatter().string(from:Date()),"score":12,"scored_sources":1,"complete":true]] }
var count=0
for language in ["zh-Hant","zh-Hans","en"] {
 ui.language=language
 for scenario in 0..<4 {
  pending=scenario==3
  let title=ui.tr(pending ? "approvalRequired":"paused")
  let body=language=="en" ? "TLS connection ended unexpectedly." : "TLS 連線意外結束。"
  let detail:[String:Any]? = scenario==0 || pending ? nil : ["stage":"egress","error_type":"SSLEOFError","raw_message":scenario==1 ? "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1006)" : String(repeating:"Long fixture diagnostic line with exact details.\n",count:35),"errno":8,"origin":"fixture.py:10"]
  ui.prepareCriticalAlert(title:title,body:body,diagnostic:detail)
  let panel=property(ui,"criticalPanel",NSPanel.self)
  panel.contentView!.layoutSubtreeIfNeeded()
  precondition(!panel.isVisible,"A layout test must not show a window")
  precondition(panel.frame.width==340)
  precondition(panel.frame.height<260,"Notice grew beyond compact size")
  let heading=property(ui,"criticalTitle",NSTextField.self)
  let bodyField=property(ui,"criticalBody",NSTextField.self)
  let technical=property(ui,"criticalTechnical",NSTextField.self)
  precondition(heading.font!.pointSize==16 && bodyField.font!.pointSize==14 && technical.font!.pointSize==12)
  let buttons=property(ui,"criticalButtons",NSStackView.self)
  for case let button as NSButton in buttons.arrangedSubviews where !button.isHidden {
   precondition(button.font!.pointSize==12)
   precondition(button.intrinsicContentSize.width<=button.frame.width+2,"Button label clipped: \(button.title)")
  }
  if scenario==2 {
   let scroll=property(ui,"criticalTechnicalScroll",NSScrollView.self)
   precondition(!scroll.isHidden && scroll.frame.height<=96 && technical.frame.height>96)
   precondition(technical.stringValue.contains("Long fixture diagnostic line"))
  }
  print(language,scenario,panel.frame.width,panel.frame.height)
  count+=1
 }
}
precondition(count==12)
'''
        with tempfile.TemporaryDirectory(prefix='guard-compact-notice-') as temp:
            folder=Path(temp)
            bundle=folder/'Notice Fixture.app/Contents'
            macos=bundle/'MacOS';macos.mkdir(parents=True)
            interface=bundle/'Resources/Interface';interface.mkdir(parents=True)
            shutil.copy2(ROOT/'interface/strings.json',interface/'strings.json')
            (bundle/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.fixture.guard-notice',
                'CFBundleExecutable':'fixture','LSUIElement':True,'CFBundlePackageType':'APPL'}))
            source=folder/'main.swift';source.write_text(code)
            result=subprocess.run(['/usr/bin/xcrun','swiftc','-module-cache-path',str(folder/'cache'),
                str(ROOT/'src/GuardPresentation.swift'),str(ROOT/'src/GuardInterface.swift'),str(source),
                '-framework','AppKit','-framework','WebKit','-o',str(macos/'fixture')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(macos/'fixture'),'--preview-ui'],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)


if __name__=='__main__':unittest.main()
