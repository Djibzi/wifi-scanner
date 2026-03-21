// menu.js — Menu natif de l'application
const { Menu, shell } = require('electron');

function createMenu(mainWindow) {
    const template = [
        {
            label: 'Fichier',
            submenu: [
                {
                    label: 'Nouveau scan',
                    accelerator: 'CmdOrCtrl+N',
                    click: () => mainWindow.webContents.send('menu-action', 'new-scan'),
                },
                { type: 'separator' },
                {
                    label: 'Exporter le rapport...',
                    accelerator: 'CmdOrCtrl+E',
                    click: () => mainWindow.webContents.send('menu-action', 'export-report'),
                },
                { type: 'separator' },
                { role: 'quit', label: 'Quitter' },
            ],
        },
        {
            label: 'Affichage',
            submenu: [
                { role: 'reload', label: 'Recharger' },
                { role: 'toggleDevTools', label: 'Outils développeur' },
                { type: 'separator' },
                { role: 'zoomIn', label: 'Zoom +' },
                { role: 'zoomOut', label: 'Zoom -' },
                { role: 'resetZoom', label: 'Taille réelle' },
                { type: 'separator' },
                { role: 'togglefullscreen', label: 'Plein écran' },
            ],
        },
        {
            label: 'Aide',
            submenu: [
                {
                    label: 'A propos de REDSHIELD',
                    click: () => mainWindow.webContents.send('menu-action', 'about'),
                },
            ],
        },
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

module.exports = { createMenu };
