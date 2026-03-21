// vulnerabilities.js — Page liste des vulnérabilités

class VulnerabilitiesPage {
    constructor() {
        this.container = null;
        this.activeTab = 'ALL';
        this._onVulnsChange = null;
    }

    mount(container) {
        this.container = container;
        this._render();

        this._onVulnsChange = () => this._render();
        store.on('vulnerabilities', this._onVulnsChange);
    }

    unmount() {
        if (this._onVulnsChange) store.off('vulnerabilities', this._onVulnsChange);
        this.container = null;
    }

    _render() {
        if (!this.container) return;
        window.vulnsPage = this;

        const vulns = store.get('vulnerabilities') || [];
        const counts = { ALL: vulns.length, CRITIQUE: 0, HAUTE: 0, MOYENNE: 0, FAIBLE: 0, INFO: 0 };
        vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

        const filtered = this.activeTab === 'ALL'
            ? vulns
            : vulns.filter(v => v.severity === this.activeTab);

        const tabs = ['ALL', 'CRITIQUE', 'HAUTE', 'MOYENNE', 'FAIBLE', 'INFO'];
        const tabLabels = { ALL: 'Toutes', CRITIQUE: 'Critiques', HAUTE: 'Hautes', MOYENNE: 'Moyennes', FAIBLE: 'Faibles', INFO: 'Info' };

        this.container.innerHTML = `
            <div class="vulns-tabs">
                ${tabs.map(tab => `
                    <div class="vuln-tab ${this.activeTab === tab ? 'active' : ''}"
                         onclick="vulnsPage._setTab('${tab}')">
                        ${tabLabels[tab]}
                        <span class="tab-count">${counts[tab]}</span>
                    </div>
                `).join('')}
            </div>

            <div id="vulns-list">
                ${filtered.length > 0
                    ? filtered.map((v, i) => VulnCard.render(v, i)).join('')
                    : '<p class="text-muted">Aucune vulnérabilité dans cette catégorie</p>'
                }
            </div>
        `;
    }

    _setTab(tab) {
        this.activeTab = tab;
        this._render();
    }
}

window.VulnerabilitiesPage = VulnerabilitiesPage;
