#!/usr/bin/env python3
"""Reproduce only in official stock Electron; never executes a Claude binary."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'src/guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

parser = argparse.ArgumentParser()
parser.add_argument('--profile-extra', default='')
parser.add_argument('--plain', action='store_true')
parser.add_argument('--permissive-outer', action='store_true')
args = parser.parse_args()
binary = Path.home() / 'Library/Caches/ClaudeGuardDevelopment/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron'
if not binary.is_file():
    raise SystemExit('Install official stock electron@44.9.3 into the development cache first.')
with tempfile.TemporaryDirectory(prefix='guard-electron-fixture-') as temp:
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(8)
        port = listener.getsockname()[1]
        profile = guard.sandbox_profile(port) + '\n' + args.profile_extra
        if args.permissive_outer:
            profile = '(version 1)(allow default)'
        env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ['ANTHROPIC', 'CLAUDE', 'PROXY', 'ELECTRON_RUN_AS_NODE'])}
        env.update(GUARD_FIXTURE_DATA=temp, GUARD_FIXTURE_PORT=str(port), ELECTRON_ENABLE_LOGGING='1')
        command = [str(binary), str(ROOT / 'tests/electron_fixture.js'), '--enable-logging=stderr', '--enable-sandbox-logging']
        if not args.plain:
            command = ['/usr/bin/sandbox-exec', '-p', profile, *command]
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=5)
        print('PROFILE', 'stock Electron baseline' if args.plain else 'guard profile', 'EXIT', proc.returncode)
        print(stdout[:6000])
        print('DIAGNOSTIC', stderr[-7000:])
        name = 'plain' if args.plain else ('permissive-outer' if args.permissive_outer else 'guard')
        out = ROOT / ('runtime/electron-reproduction-' + name + '.json')
        out.write_text(json.dumps({'plain':args.plain, 'permissive_outer':args.permissive_outer,'profile_extra':args.profile_extra,
                                   'exit':proc.returncode, 'stdout':stdout[:12000], 'stderr':stderr[-16000:]}, indent=2))
        raise SystemExit(0 if proc.returncode == 0 and '"kind":"FIXTURE_OK"' in stdout else 1)
