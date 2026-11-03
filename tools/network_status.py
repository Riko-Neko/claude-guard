#!/usr/bin/env python3
"""Read only local Clash/macOS mode; never probe an external IP or open Claude."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import guard
import environment_checks

def read_status(settings):
    try:config=guard.controller(settings,'configs')
    except Exception:config={}
    try:proxy=environment_checks.system_proxy_enabled(environment_checks.command(['/usr/sbin/scutil','--proxy']))
    except Exception:proxy=None
    return environment_checks.network_mode(config,proxy)

if __name__=='__main__':
    try:settings=json.loads((ROOT/'settings.json').read_text())
    except (OSError,ValueError):settings={}
    print(json.dumps(read_status(settings)),flush=True)
