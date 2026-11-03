"""Only GUI refresh is allowed; no real app, provider or account is used."""
import sys
import plistlib
from pathlib import Path
from unittest import mock
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import refresh_lulu_ui as gui

class GUITests(unittest.TestCase):
    def test_pid_selection_excludes_network_extension_other_users_and_other_apps(self):
        rows='501 10 /Applications/LuLu.app/Contents/MacOS/LuLu\n0 11 /Library/SystemExtensions/x/com.objective-see.lulu.extension\n502 12 /Applications/LuLu.app/Contents/MacOS/LuLu\n501 13 /Applications/Claude.app/Contents/MacOS/Claude'
        with mock.patch.object(gui.os,'getuid',return_value=501),mock.patch.object(gui.subprocess,'check_output',return_value=rows):
            self.assertEqual(gui.gui_pids(),[10])
    def test_only_gui_is_signaled_and_official_quit_is_never_called(self):
        prefs=mock.Mock();prefs.read_bytes.return_value=plistlib.dumps({'noIconMode':True,'installTime':'done'})
        with mock.patch.object(gui,'PREFS',prefs),mock.patch.object(gui.subprocess,'run',return_value=mock.Mock(stderr='TeamIdentifier=VBG97UB4TA')) as run,mock.patch.object(gui,'gui_pids',side_effect=[[10],[10],[]]),mock.patch.object(gui.os,'kill') as stop:
            gui.refresh()
        stop.assert_called_once_with(10,gui.signal.SIGTERM)
        self.assertEqual(run.call_args.args[0],['/usr/bin/open','-g','-a',str(gui.APP)])
        self.assertFalse(any('-quit' in c.args[0] for c in run.call_args_list))
    def test_unfinished_onboarding_or_visible_setting_never_stops_any_process(self):
        for values in ({'noIconMode':True},{'noIconMode':False,'installTime':'done'}):
            prefs=mock.Mock();prefs.read_bytes.return_value=plistlib.dumps(values)
            with mock.patch.object(gui,'PREFS',prefs),mock.patch.object(gui.os,'kill') as stop:
                with self.assertRaises(RuntimeError):gui.refresh()
            stop.assert_not_called()

if __name__=='__main__':unittest.main()
