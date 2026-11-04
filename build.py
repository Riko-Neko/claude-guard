#!/usr/bin/env python3
"""Build a self-contained app payload and macOS installer. Never installs or launches."""
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
VERSION = '0.13.2'
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
TOOLS = ['gui_setup.py', 'configure_vpn.py', 'ensure_lulu.py', 'initialize_filter.py', 'recover_lulu_storage.py',
         'lulu_setup.py', 'check_lulu_maintenance.py', 'build_network_fixture.py', 'enable_user_trial.py', 'admin_authorization.py', 'lifecycle.py', 'uninstall_cleanup.py', 'install_preparation.py', 'refresh_lulu_ui.py', 'leak_wizard.py', 'network_status.py']
with tempfile.TemporaryDirectory(prefix='claude-guard-package-') as directory:
    stage = Path(directory)
    payload = stage / 'payload'
    app = payload / 'Applications/Claude Guard.app'
    macos = app / 'Contents/MacOS'
    resources = app / 'Contents/Resources'
    macos.mkdir(parents=True)
    resources.mkdir()
    runtime = resources / 'Runtime'
    runtime.mkdir()
    (runtime / 'src').mkdir()
    for source in (ROOT / 'src').glob('*.py'):
        shutil.copy2(source, runtime / 'src' / source.name)
    (runtime / 'tools').mkdir()
    for name in TOOLS:
        shutil.copy2(ROOT / 'tools' / name, runtime / 'tools' / name)
    (runtime / 'tests').mkdir()
    for name in ['verify_lulu_flow.py', 'lulu_probe.c']:
        shutil.copy2(ROOT / 'tests' / name, runtime / 'tests' / name)
    shutil.copy2(ROOT / 'README.md', runtime / 'README.md')
    shutil.copy2(ROOT / 'README.zh-CN.md', runtime / 'README.zh-CN.md')
    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
        shutil.copy2(ROOT / name, runtime / name)
    (runtime / 'docs').mkdir()
    for name in ('IP_REPUTATION.md', 'DOMAIN_CHECKS.md'):
        shutil.copy2(ROOT / 'docs' / name, runtime / 'docs' / name)
    (runtime / 'assets').mkdir()
    shutil.copy2(ROOT / 'assets/connection-flow.svg', runtime / 'assets/connection-flow.svg')
    shutil.copytree(ROOT / 'interface', resources / 'Interface')
    shutil.copy2(ROOT / 'settings.example.json', runtime / 'settings.example.json')
    shutil.copy2(ROOT / 'assets/Guard.icns', resources / 'Guard.icns')
    for source, target in [('ClaudeGuard.png', 'Guard.png'), ('GuardMenu.png', 'GuardMenu.png')]:
        shutil.copy2(ROOT / 'assets' / source, resources / target)
    info = {'CFBundleIdentifier': 'local.rikoneko.claude-guard', 'CFBundleName': 'Claude Guard',
            'CFBundleDisplayName': 'Claude Guard', 'CFBundleExecutable': 'ClaudeGuard',
            'CFBundleIconFile': 'Guard.icns', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '36', 'CFBundleShortVersionString': VERSION,
            'LSUIElement': True, 'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True}
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    shutil.copy2(ROOT / 'src/ClaudeGuard.swift', stage / 'main.swift')
    subprocess.run(['/usr/bin/xcrun', 'swiftc', '-O', '-module-cache-path', str(stage / 'ModuleCache'), str(ROOT / 'src/GuardPresentation.swift'), str(ROOT / 'src/GuardInterface.swift'), str(stage / 'main.swift'),
                    '-framework', 'AppKit', '-framework', 'UserNotifications', '-framework', 'SystemConfiguration', '-framework', 'WebKit',
                    '-o', str(macos / 'ClaudeGuard')], check=True)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(app)], check=True, capture_output=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True, capture_output=True)
    # Legacy local entry gets the same standalone app, never a development pointer.
    with zipfile.ZipFile(ROOT / 'ClaudeGuard-runtime.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in app.rglob('*'):
            if path.is_file(): archive.write(path, path.relative_to(app.parent))
    scripts = stage / 'scripts'
    scripts.mkdir()
    (scripts / 'preinstall').write_text('''#!/bin/sh
set -eu
if /bin/ps -axo comm= | /usr/bin/grep -Eq '/Claude[.]app/|/Claude/claude-code/|(^|/)claude$|/Claude Guard[.]app/Contents/MacOS/ClaudeGuard$'; then
    echo '请先完全退出 Claude、Claude Code 和 Claude Guard，再安装。' >&2
    exit 1
fi
''')
    (scripts / 'postinstall').write_text('''#!/bin/sh
set -eu
state='/Library/Application Support/Claude Guard'
if [ -L "$state" ] || [ -L "$state/package-installation-id" ]; then exit 1; fi
/bin/mkdir -p "$state"
/usr/sbin/chown root:wheel "$state"
/bin/chmod 755 "$state"
/usr/bin/uuidgen > "$state/package-installation-id"
/usr/sbin/chown root:wheel "$state/package-installation-id"
/bin/chmod 644 "$state/package-installation-id"
# Launch the configuration window in the logged-in user's session, never as root.
# The app only opens its configuration UI; it does not start Claude or install LuLu.
if [ "$3" = / ]; then
    console_user=$(/usr/bin/stat -f '%Su' /dev/console)
    if [ "$console_user" != root ] && [ "$console_user" != loginwindow ]; then
        console_uid=$(/usr/bin/id -u "$console_user")
        /bin/launchctl asuser "$console_uid" /usr/bin/sudo -H -u "$console_user" /usr/bin/env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND /usr/bin/open '/Applications/Claude Guard.app' || /usr/bin/logger -t ClaudeGuardInstaller 'Open Claude Guard from Applications to configure.'
    fi
fi
''')
    for script in scripts.iterdir(): script.chmod(0o755)
    components = stage / 'components.plist'
    components.write_bytes(plistlib.dumps([{'RootRelativeBundlePath': 'Applications/Claude Guard.app',
        'BundleIsRelocatable': False, 'BundleHasStrictIdentifier': True, 'BundleOverwriteAction': 'upgrade'}]))
    subprocess.run(['/usr/bin/pkgbuild', '--root', str(payload), '--scripts', str(scripts),
                    '--component-plist', str(components),
                    '--identifier', 'local.rikoneko.claude-guard.installer', '--version', VERSION,
                    '--install-location', '/', str(DIST / f'ClaudeGuard-{VERSION}.pkg')], check=True)
print('Built installer; nothing installed or launched:', DIST / f'ClaudeGuard-{VERSION}.pkg')
