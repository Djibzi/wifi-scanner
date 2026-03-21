// scan.js — Page Scanner

class ScanPage {
    constructor() {
        this.container = null;
        this.terminal = new TerminalComponent();
        this._onProgress = null;
        this._onScanning = null;
    }

    mount(container) {
        this.container = container;
        window.scanPage = this;
        this._render();

        this._onProgress = (val) => this._updateProgress(val);
        this._onScanning = (val) => this._render();
        store.on('scanProgress', this._onProgress);
        store.on('scanning', this._onScanning);
    }

    unmount() {
        if (this._onProgress) store.off('scanProgress', this._onProgress);
        if (this._onScanning) store.off('scanning', this._onScanning);
        this.terminal.unmount();
        window.scanPage = null;
        this.container = null;
    }

    getHeaderActions() {
        const scanning = store.get('scanning');
        if (scanning) {
            return '<button class="btn btn-danger btn-sm" onclick="scanPage._stopScan()">Arrêter</button>';
        }
        return '';
    }

    onModuleComplete(data) {
        // Mettre à jour la carte du module
        const card = document.getElementById(`module-${data.module}`);
        if (card) {
            card.classList.remove('module-running');
            card.classList.add('module-done');
        }
    }

    async _startScan() {
        const modeSelect = document.getElementById('scan-mode');
        const targetInput = document.getElementById('scan-target');
        const mode = modeSelect ? modeSelect.value : 'quick';
        const target = targetInput ? targetInput.value.trim() : '';

        try {
            await api.startScan(mode, target);
        } catch (e) {
            Toast.error('Erreur', e.message);
        }
    }

    async _stopScan() {
        try {
            await api.stopScan();
            store.set('scanning', false);
            Toast.info('Scan arrêté', '');
        } catch (e) {
            Toast.error('Erreur', e.message);
        }
    }

    _updateProgress(percent) {
        const fill = this.container?.querySelector('.progress-fill');
        const percentEl = document.getElementById('scan-percent');
        const moduleEl = document.getElementById('scan-module-name');

        if (fill) fill.style.width = `${percent}%`;
        if (percentEl) percentEl.textContent = `${percent}%`;
        if (moduleEl) moduleEl.textContent = store.get('scanModule') || '';
    }

    _render() {
        if (!this.container) return;
        const scanning = store.get('scanning');
        const progress = store.get('scanProgress') || 0;

        const modules = [
            'WiFi', 'Découverte', 'Ports', 'Services', 'OS', 'Vulnérabilités', 'DNS'
        ];

        this.container.innerHTML = `
            <!-- Config de scan -->
            ${!scanning ? `
            <div class="scan-header-info">
                <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
                    <select class="select" id="scan-mode">
                        <option value="quick">Rapide (top 37 ports)</option>
                        <option value="normal">Normal (top 100 ports)</option>
                        <option value="full">Complet (top 1000 ports)</option>
                    </select>
                    <input class="input" id="scan-target" placeholder="Cible (IP ou vide = réseau local)" style="width:250px">
                    <button class="btn btn-primary" onclick="scanPage._startScan()">Lancer le scan</button>
                </div>
            </div>
            ` : ''}

            <!-- Barre de progression -->
            <div class="scan-progress-section">
                <div class="scan-progress-label">
                    <span class="scan-progress-module" id="scan-module-name">${store.get('scanModule') || 'En attente...'}</span>
                    <span class="scan-progress-percent" id="scan-percent">${progress}%</span>
                </div>
                ${ProgressBar.render(progress, true)}
            </div>

            <!-- Grille des modules -->
            <div class="scan-modules-grid">
                ${modules.map(name => `
                    <div class="scan-module-card" id="module-${name}">
                        <div class="module-status-dot"></div>
                        <span style="font-size:0.85rem">${name}</span>
                    </div>
                `).join('')}
            </div>

            <!-- Split : découvertes + terminal -->
            <div class="scan-split">
                <div class="scan-discoveries">
                    <h3>Découvertes en direct</h3>
                    <div id="scan-discoveries-list">
                        ${this._renderDiscoveries()}
                    </div>
                </div>
                <div class="scan-terminal-section">
                    ${this.terminal.render()}
                </div>
            </div>
        `;

        this.terminal.mount();
    }

    _renderDiscoveries() {
        const hosts = store.get('hosts') || [];
        if (hosts.length === 0) return '<p class="text-muted">En attente de découvertes...</p>';

        return hosts.map(h => `
            <div class="discovery-item">
                <span class="badge badge-info">HOST</span>
                <span class="mono">${h.ip}</span>
                <span class="text-muted">${h.vendor || ''}</span>
            </div>
        `).join('');
    }
}

window.ScanPage = ScanPage;
