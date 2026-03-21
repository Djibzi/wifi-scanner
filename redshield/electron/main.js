// main.js — Fenêtre principale Electron + lancement Python
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

// Référence globale pour éviter le garbage collection
let mainWindow = null;
let pythonManager = null;
const isDev = process.argv.includes('--dev');

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        title: 'REDSHIELD',
        icon: path.join(__dirname, '..', 'frontend', 'assets', 'app-icon.ico'),
        backgroundColor: '#0d0b0e',
        show: false,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    mainWindow.loadFile(path.join(__dirname, '..', 'frontend', 'index.html'));

    // Afficher quand prêt pour éviter le flash blanc
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    if (isDev) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

async function startApp() {
    createWindow();

    // Charger le menu et python-manager après le lancement
    try {
        const { createMenu } = require('./menu');
        createMenu(mainWindow);
    } catch (e) {
        console.error('Menu error:', e.message);
    }

    // Lancer le backend Python
    try {
        const PythonManager = require('./python-manager');
        pythonManager = new PythonManager();
        const port = await pythonManager.start();
        mainWindow.webContents.on('did-finish-load', () => {
            mainWindow.webContents.send('backend-port', port);
        });
    } catch (err) {
        console.error('Erreur lancement backend Python:', err.message);
        mainWindow.webContents.on('did-finish-load', () => {
            mainWindow.webContents.send('backend-error', err.message);
        });
    }
}

app.whenReady().then(startApp);

app.on('window-all-closed', () => {
    if (pythonManager) {
        pythonManager.stop();
    }
    app.quit();
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});

// IPC : le frontend demande le port backend
ipcMain.handle('get-backend-port', () => {
    return pythonManager ? pythonManager.port : null;
});

// IPC : le frontend demande de relancer Python
ipcMain.handle('restart-backend', async () => {
    if (pythonManager) {
        pythonManager.stop();
        return await pythonManager.start();
    }
    return null;
});
