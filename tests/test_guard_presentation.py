"""Compile the real notification/state code with fake effects; no app or network."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class PresentationTests(unittest.TestCase):
    def test_notification_failure_state_and_report_freshness(self):
        script=r'''import Foundation
var order:[String]=[];var errors:[[String:Any]]=[]
GuardNoticeDelivery.send(alarm:true,showInApp:{order.append("visible")},authorize:{reply in
 order.append("authorize");reply(false,NSError(domain:"fixture.notifications",code:1))
},post:{_ in preconditionFailure("Denied authorization must not post")},record:{errors.append($0)})
precondition(order == ["visible","authorize"])
precondition(errors.first?["kind"] as? String == "NOTIFICATION_AUTH_FAILED")
precondition(errors.first?["domain"] as? String == "fixture.notifications")
precondition(errors.first?["code"] as? Int == 1)
var visible=0
GuardNoticeDelivery.send(alarm:true,showInApp:{visible+=1},authorize:{$0(true,nil)},post:{$0(NSError(domain:"fixture.delivery",code:99))},record:{errors.append($0)})
precondition(visible==1 && errors.last?["kind"] as? String == "NOTIFICATION_SEND_FAILED")
GuardNoticeDelivery.send(alarm:false,showInApp:{preconditionFailure("Routine message opened critical UI")},authorize:{$0(false,nil)},post:{_ in},record:{_ in})
var state=GuardConnectionPresentation()
state.beginCheck()
state.receive(["kind":"IP_CHANGED","time":"2026-01-01T10:01:00Z","ip":"192.0.2.2","country":"TW","message":"Fixture changed exit"])
state.receive(["kind":"CHECK_FAILED","message":"Generic failure"])
state.backendEnded()
precondition(state.statusKey=="approvalRequired" && state.approvalRequired)
precondition(state.reason=="Fixture changed exit" && state.observedIP=="192.0.2.2")
state.restoreHistory()
precondition(state.statusKey=="approvalRequired")
state.receive(["kind":"IDLE"])
precondition(state.approvalRequired)
state.beginCheck();state.receive(["kind":"CHECK_FAILED","message":"still wrong"])
precondition(state.statusKey=="approvalRequired")
state.receive(["kind":"CHECK_COMPLETE"])
precondition(!state.approvalRequired && state.reason.isEmpty)
state.beginCheck();state.backendEnded()
precondition(state.statusKey=="connectionFailed")
state.receive(["kind":"RUNNING"]);state.backendEnded()
precondition(state.statusKey=="paused")
let now=GuardReportFreshness.date("2026-01-01T12:00:00Z")!
precondition(GuardReportFreshness.stale(time:"2026-01-01T09:00:00Z",invalidatedAt:"",maxAge:3600,now:now))
precondition(GuardReportFreshness.stale(time:"2026-01-01T11:55:00Z",invalidatedAt:"2026-01-01T11:58:00Z",maxAge:3600,now:now))
precondition(GuardReportFreshness.stale(time:"invalid",invalidatedAt:"",maxAge:3600,now:now))
precondition(!GuardReportFreshness.stale(time:"2026-01-01T11:59:00.000+00:00",invalidatedAt:"2026-01-01T11:58:00Z",maxAge:3600,now:now))
print("Critical alert fallback, failed-state retention and report freshness passed")
'''
        with tempfile.TemporaryDirectory(prefix='guard-presentation-test-') as temp:
            root=Path(temp);(root/'main.swift').write_text(script)
            result=subprocess.run(['/usr/bin/xcrun','swiftc','-module-cache-path',str(root/'cache'),str(ROOT/'src/GuardPresentation.swift'),str(root/'main.swift'),'-o',str(root/'probe')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(root/'probe')],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
