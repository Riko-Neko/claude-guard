// Standalone, account-free Electron fixture. Never imports Claude code or data.
const { app, BrowserWindow, session } = require('electron');
const path = require('path');
app.setName('Guard Compatibility Fixture');
app.setActivationPolicy('prohibited');
app.setPath('userData', process.env.GUARD_FIXTURE_DATA);
app.commandLine.appendSwitch('disable-background-networking');
let failed = false;
let window;
function report(kind, extra = {}) {
  process.stdout.write(JSON.stringify({ kind, ...extra }) + '\n');
}
app.on('child-process-gone', (_event, details) => {
  if (!['clean-exit', 'killed'].includes(details.reason)) {
    failed = true;
    report('CHILD_FAILED', { type: details.type, reason: details.reason, code: details.exitCode });
  }
});
app.whenReady().then(async () => {
  await session.defaultSession.setProxy({ proxyRules: `http=127.0.0.1:${process.env.GUARD_FIXTURE_PORT};https=127.0.0.1:${process.env.GUARD_FIXTURE_PORT}`,
    proxyBypassRules: '<-loopback>' });
  window = new BrowserWindow({ show: false, webPreferences: {
    contextIsolation: true, sandbox: true, nodeIntegration: false,
    preload: path.join(__dirname, 'electron_preload.js'),
  } });
  window.webContents.on('render-process-gone', (_e, details) => {
    failed = true; report('RENDER_FAILED', { reason: details.reason, code: details.exitCode });
  });
  const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'"><title>Offline Guard Fixture</title><body>fixture-ready</body>`;
  await window.loadURL('data:text/html;base64,' + Buffer.from(html).toString('base64'));
  const rendered = await window.webContents.executeJavaScript('document.body.textContent');
  if (rendered !== 'fixture-ready') throw Error('renderer did not complete');
  const security = await window.webContents.executeJavaScript('window.fixtureSecurity');
  if (!security.sandboxed || !security.contextIsolated) throw Error('native Electron security not active');
  report('RENDER_OK', security);
  setTimeout(() => { report(failed ? 'FIXTURE_FAILED' : 'FIXTURE_OK'); app.exit(failed ? 31 : 0); }, 1500);
}).catch(error => { report('FIXTURE_ERROR', { message: String(error.message) }); app.exit(32); });
setTimeout(() => { report('FIXTURE_TIMEOUT'); app.exit(33); }, 9000);
