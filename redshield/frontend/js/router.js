// router.js — Routeur SPA pour la navigation entre pages

class Router {
    constructor() {
        this.pages = {};
        this.currentPage = null;
    }

    register(name, pageInstance) {
        this.pages[name] = pageInstance;
    }

    navigate(pageName) {
        if (this.currentPage === pageName) return;

        // Mettre à jour la nav active
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === pageName);
        });

        // Mettre à jour le titre
        const titles = {
            'dashboard': 'Dashboard',
            'scan': 'Scanner',
            'network-map': 'Carte réseau',
            'radar': 'Radar',
            'hosts': 'Appareils',
            'host-detail': 'Détail appareil',
            'vulnerabilities': 'Vulnérabilités',
            'traffic': 'Trafic réseau',
            'report': 'Rapport',
            'settings': 'Paramètres',
        };

        const titleEl = document.getElementById('page-title');
        if (titleEl) {
            titleEl.textContent = titles[pageName] || pageName;
        }

        // Démonter la page actuelle
        if (this.currentPage && this.pages[this.currentPage]) {
            this.pages[this.currentPage].unmount();
        }

        // Monter la nouvelle page
        this.currentPage = pageName;
        const content = document.getElementById('page-content');
        if (content) {
            content.innerHTML = '';
            const wrapper = document.createElement('div');
            wrapper.className = 'page-enter';
            content.appendChild(wrapper);

            if (this.pages[pageName]) {
                this.pages[pageName].mount(wrapper);
            } else {
                wrapper.innerHTML = `<p class="text-muted">Page "${pageName}" en cours de développement...</p>`;
            }
        }

        // Vider les actions du header
        const actionsEl = document.getElementById('page-actions');
        if (actionsEl) {
            actionsEl.innerHTML = '';
            if (this.pages[pageName] && this.pages[pageName].getHeaderActions) {
                actionsEl.innerHTML = this.pages[pageName].getHeaderActions();
            }
        }
    }

    // Navigation vers le détail d'un hôte
    navigateToHost(ip) {
        const titleEl = document.getElementById('page-title');
        if (titleEl) titleEl.textContent = ip;

        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === 'hosts');
        });

        if (this.currentPage && this.pages[this.currentPage]) {
            this.pages[this.currentPage].unmount();
        }

        this.currentPage = 'host-detail';
        const content = document.getElementById('page-content');
        if (content) {
            content.innerHTML = '';
            const wrapper = document.createElement('div');
            wrapper.className = 'page-enter';
            content.appendChild(wrapper);

            if (this.pages['host-detail']) {
                this.pages['host-detail'].mount(wrapper, ip);
            }
        }
    }
}

window.router = new Router();
