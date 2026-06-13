const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('netfix', {
  run: (options) => ipcRenderer.invoke('backend:run', options),
  backendStatus: () => ipcRenderer.invoke('app:backendStatus'),
  installNpcap: () => ipcRenderer.invoke('app:installNpcap'),
  openPath: (targetPath) => ipcRenderer.invoke('app:openPath', targetPath),
  openReports: () => ipcRenderer.invoke('app:openReports'),
  restartElevated: () => ipcRenderer.invoke('app:restartElevated')
});
