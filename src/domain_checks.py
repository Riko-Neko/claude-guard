"""Weighted domain audit. Queries are injected; this module never dials directly.

A trace IP is site evidence, a pinned route is only local routing evidence.
Wildcard coverage is never represented as a wildcard-wide IP observation.
"""
import concurrent.futures
import copy
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import threading
import time

GEOSITE_HOST = 'raw.githubusercontent.com'
GEOSITE_PATH = '/MetaCubeX/meta-rules-dat/meta/geo/geosite/anthropic.list'
# Core scopes are prerequisites, not samples claiming every subdomain was contacted.
TARGETS = (
    dict(domain='anthropic.com', scope='suffix', weight=15, core=True),
    dict(domain='claude.ai', scope='suffix', weight=15, core=True),
    dict(domain='api.anthropic.com', scope='host', weight=10),
    dict(domain='claude.com', scope='suffix', weight=8, probe=True),
    dict(domain='platform.claude.com', scope='host', weight=8),
    dict(domain='sso.claude.com', scope='host', weight=6),
    dict(domain='mcp-proxy.anthropic.com', scope='host', weight=5),
    dict(domain='claudeusercontent.com', scope='suffix', weight=4),
    dict(domain='claudemcpcontent.com', scope='suffix', weight=4),
    dict(domain='assets-proxy.anthropic.com', scope='host', weight=3),
    dict(domain='downloads.claude.ai', scope='host', weight=3),
    dict(domain='bridge.claudeusercontent.com', scope='host', weight=3),
    dict(domain='claude.app', scope='suffix', weight=3),
    dict(domain='statsig.anthropic.com', scope='host', weight=1),
    dict(domain='http-intake.logs.us5.datadoghq.com', scope='host', weight=1),
    dict(domain='browser-intake-us5-datadoghq.com', scope='host', weight=1),
)


def timestamp():
    return datetime.datetime.now().astimezone().isoformat()


def hostname(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('invalid hostname')
    value = value.lower()
    if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise ValueError('invalid hostname')
    return value


def covered(entry, target):
    return (entry['domain'] == target['domain'] and
            (target['scope'] == 'suffix' or entry['scope'] == 'host')) or (
        target['scope'] == 'suffix' and entry['domain'].endswith('.' + target['domain']))


def parse_geosite(data):
    """Fail closed on unsupported formats, rather than silently claiming completeness."""
    if not isinstance(data, bytes) or len(data) > 131072:
        raise ValueError('invalid geosite size')
    entries = {}
    for line in data.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        suffix = line.startswith('+.')
        domain = hostname(line[2:] if suffix else line)
        entries[(domain, suffix)] = dict(domain=domain, scope='suffix' if suffix else 'host')
    if not entries or len(entries) > 2048:
        raise ValueError('empty or oversized geosite')
    all_entries = list(entries.values())
    supplemental = [entry for entry in all_entries if not any(covered(entry, t) for t in TARGETS)]
    return dict(status='ok', total_entries=len(all_entries), sha256=hashlib.sha256(data).hexdigest(),
                entries=supplemental, source='https://' + GEOSITE_HOST + GEOSITE_PATH)


def trace_ip(status, data, host):
    """Only accept a bounded Cloudflare trace body from this exact HTTPS target."""
    if status != 200 or not isinstance(data, bytes) or len(data) > 16384:
        return None
    try:
        lines = data.decode('ascii').splitlines()
        pairs = [line.split('=', 1) for line in lines if '=' in line]
        if len(pairs) != len({pair[0] for pair in pairs}):
            return None
        fields = dict(pairs)
        ip = ipaddress.ip_address(fields.get('ip', ''))
        if (not ip.is_global or fields.get('h', '').lower() != host or
                not re.fullmatch(r'[A-Z]{2}', fields.get('loc', '')) or not fields.get('colo')):
            return None
        return str(ip)
    except (UnicodeError, ValueError):
        return None


def score(rows, geosite):
    core = [r for r in rows if r.get('core')]
    mismatch = any(r.get('status') == 'mismatch' for r in rows)
    core_failure = any(r.get('status') == 'failed' and any(
        r['domain'] == d or r['domain'].endswith('.' + d) for d in ('anthropic.com', 'claude.ai')) for r in rows)
    if mismatch or core_failure:
        return 0
    if len(core) != 2 or not all(r.get('status') == 'passed' for r in core):
        return None
    points = sum(r['weight'] for r in rows if r.get('status') == 'passed')
    if points == 90 and geosite.get('status') == 'ok':
        extra = geosite.get('entries', [])
        # Empty validated supplement means the primary scopes already cover the dataset.
        points += 10 if not extra else 10 * sum(r.get('status') == 'passed' for r in extra) // len(extra)
    return points


class Monitor:
    def __init__(self, query, route_check, publish, path, interval=3600):
        self.query = query
        self.route_check = route_check
        self.publish = publish
        self.path = Path(path)
        self.interval = max(3600, interval)
        self.lock = threading.RLock()
        self.finished = threading.Event()
        self.finished.set()
        self.closed = False
        self.generation = 0
        self.current_ip = None
        self.last_started = 0
        self.rows = []
        self.geosite = {}

    def request(self, ip, force=False):
        ip = str(ipaddress.ip_address(ip))
        with self.lock:
            if self.closed or (ip == self.current_ip and (not self.finished.is_set() or
                    (not force and time.monotonic() - self.last_started < self.interval))):
                return
            self.generation += 1
            generation = self.generation
            self.current_ip = ip
            self.last_started = time.monotonic()
            self.started_at = timestamp()
            self.finished.clear()
            self.rows = [{**t, 'status': 'pending', 'method': 'pending'} for t in TARGETS]
            self.geosite = dict(status='pending', entries=[])
            self._publish()
            threading.Thread(target=self._run, args=(generation, ip), daemon=True).start()

    def _valid(self, generation):
        return not self.closed and generation == self.generation

    def _route(self):
        if self.closed:
            return False
        try:
            return self.route_check() is True
        except Exception:
            return False

    def _target(self, target, ip):
        row = {**target, 'checked_at': timestamp(), 'method': 'route', 'status': 'failed'}
        if not self._route():
            return row
        # Wildcards/scopes are proved by the unconditional pinned route, never sampled.
        if target['scope'] == 'suffix' and not (target.get('core') or target.get('probe')):
            row['status'] = 'passed'
            return row
        try:
            status, body = self.query(target['domain'], '/cdn-cgi/trace', 16384)
            observed = trace_ip(status, body, target['domain'])
            row['trace_status'] = status
            if observed:
                row.update(method='trace', observed_ip=observed,
                           status='passed' if observed == ip else 'mismatch')
            else:
                row.update(status='passed', trace_result='unsupported')
        except Exception as error:
            # A transport failure is not evidence of a different IP. Keep local route
            # evidence distinct, with the trace failure visible in expanded details.
            row.update(status='passed', trace_result='unavailable', error_type=type(error).__name__)
        if not self._route() and row['status'] != 'mismatch':
            row['status'] = 'failed'
        row['checked_at'] = timestamp()
        return row

    def _geosite(self):
        try:
            if not self._route():
                raise ValueError('route unavailable')
            status, data = self.query(GEOSITE_HOST, GEOSITE_PATH, 131072)
            if status != 200:
                raise ValueError('geosite unavailable')
            report = parse_geosite(data)
            valid = self._route()
            report['entries'] = [{**r, 'status': 'passed' if valid else 'failed', 'method': 'route'}
                                 for r in report['entries']]
            return report
        except Exception as error:
            return dict(status='unavailable', entries=[], error_type=type(error).__name__)

    def _run(self, generation, ip):
        # All I/O is bounded in the injected transport, at most four concurrent requests.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            work = {executor.submit(self._target, target, ip): index for index, target in enumerate(TARGETS)}
            work[executor.submit(self._geosite)] = None
            for future in concurrent.futures.as_completed(work):
                with self.lock:
                    if not self._valid(generation):
                        for pending in work:
                            pending.cancel()
                        return
                    index = work[future]
                    try:
                        result = future.result()
                    except Exception:
                        result = dict(status='unavailable', entries=[]) if index is None else {
                            **TARGETS[index], 'status': 'failed', 'method': 'route'}
                    if index is None:
                        self.geosite = result
                    else:
                        self.rows[index] = result
                    self._publish()
            with self.lock:
                if self._valid(generation):
                    self.finished.set()

    def _publish(self):
        report = dict(ip=self.current_ip, score=score(self.rows, self.geosite), rows=copy.deepcopy(self.rows),
                      geosite=copy.deepcopy(self.geosite), checked_at=timestamp(), started_at=self.started_at,
                      complete=all(r['status'] != 'pending' for r in self.rows) and self.geosite['status'] != 'pending',
                      method='weighted_trace_and_pinned_route', scope='guard_connections_only')
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps(report, ensure_ascii=False) + '\n')
            temporary.chmod(0o600)
            temporary.replace(self.path)
        except OSError:
            pass
        self.publish(report)

    def close(self):
        with self.lock:
            self.closed = True
            self.generation += 1
            self.finished.set()
