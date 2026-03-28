// app.js — Initialisation de l'application REDSHIELD

class App {
    constructor() {
        this.init();
    }

    async init() {
        // Écouter les clics sur la navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                if (page) router.navigate(page);
            });
        });

        // Toggle thème
        const themeBtn = document.getElementById('theme-toggle');
        if (themeBtn) {
            themeBtn.addEventListener('click', () => theme.toggle());
        }

        // Enregistrer les pages
        router.register('dashboard', new DashboardPage());
        router.register('scan', new ScanPage());
        router.register('network-map', new NetworkMapPage());
        router.register('radar', new RadarPage());
        router.register('hosts', new HostsPage());
        router.register('host-detail', new HostDetailPage());
        router.register('vulnerabilities', new VulnerabilitiesPage());
        router.register('traffic', new TrafficPage());
        router.register('report', new ReportPage());
        router.register('settings', new SettingsPage());
        router.register('portal', new PortalPage());

        // Connexion au backend
        await this._connectBackend();

        // Naviguer vers le dashboard
        router.navigate('dashboard');

        // Écouter les actions du menu natif (Electron)
        if (window.electronAPI) {
            window.electronAPI.onBackendPort((port) => {
                this._setupBackend(port);
            });

            window.electronAPI.onBackendError((error) => {
                Toast.error('Erreur backend', error);
            });
        }
    }

    async _connectBackend() {
        // Mode Electron : récupérer le port via IPC
        if (window.electronAPI) {
            const port = await window.electronAPI.getBackendPort();
            if (port) {
                this._setupBackend(port);
            }
        } else {
            // Mode navigateur (dev) : utiliser le port par défaut
            this._setupBackend(5678);
        }
    }

    _setupBackend(port) {
        store.set('backendPort', port);
        api.setPort(port);
        ws.connect(port);

        // Vérifier la santé du backend
        api.health().then((data) => {
            if (data && data.status === 'ok') {
                store.set('backendOnline', true);
                Toast.success('Connecté', `Backend REDSHIELD v${data.version}`);
            }
        }).catch(() => {
            store.set('backendOnline', false);
        });
    }
}

// Lancer l'application
document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
});
