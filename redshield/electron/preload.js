// preload.js — Bridge sécurisé entre Electron et le frontend
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Récupérer le port du backend Python
    getBackendPort: () => ipcRenderer.invoke('get-backend-port'),

    // Relancer le backend Python
    restartBackend: () => ipcRenderer.invoke('restart-backend'),

    // Écouter le port backend quand il est prêt
    onBackendPort: (callback) => {
        ipcRenderer.on('backend-port', (_event, port) => callback(port));
    },

    // Écouter les erreurs backend
    onBackendError: (callback) => {
        ipcRenderer.on('backend-error', (_event, error) => callback(error));
    },

    // Infos plateforme
    platform: process.platform,
});
