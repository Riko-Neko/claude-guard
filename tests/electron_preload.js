const { contextBridge } = require('electron');
contextBridge.exposeInMainWorld('fixtureSecurity', {
  sandboxed: process.sandboxed === true,
  contextIsolated: process.contextIsolated === true,
});
