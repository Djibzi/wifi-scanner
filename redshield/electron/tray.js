// tray.js — Icône dans la barre système
const { Tray, Menu, nativeImage } = require('electron');
const path = require('path');

class TrayManager {
    constructor(mainWindow) {
        this.tray = null;
        this.mainWindow = mainWindow;
    }

    create() {
        const iconPath = path.join(__dirname, '..', 'frontend', 'assets', 'app-icon.png');

        // Créer un icône vide si le fichier n'existe pas
        let icon;
        try {
            icon = nativeImage.createFromPath(iconPath);
        } catch {
            icon = nativeImage.createEmpty();
        }

        this.tray = new Tray(icon);
        this.tray.setToolTip('REDSHIELD — Scanner WiFi');

        const contextMenu = Menu.buildFromTemplate([
            {
                label: 'Ouvrir REDSHIELD',
                click: () => {
                    this.mainWindow.show();
                    this.mainWindow.focus();
                },
            },
            { type: 'separator' },
            {
                label: 'Lancer un scan',
                click: () => {
                    this.mainWindow.show();
                    this.mainWindow.webContents.send('menu-action', 'new-scan');
                },
            },
            { type: 'separator' },
            {
                label: 'Quitter',
                click: () => {
                    this.mainWindow.destroy();
                },
            },
        ]);

        this.tray.setContextMenu(contextMenu);

        this.tray.on('click', () => {
            this.mainWindow.show();
            this.mainWindow.focus();
        });
    }

    destroy() {
        if (this.tray) {
            this.tray.destroy();
            this.tray = null;
        }
    }
}

module.exports = TrayManager;
