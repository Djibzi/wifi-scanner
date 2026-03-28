// portal-spoofer.js — Composant interface de MAC spoofing (onglet Spoofer)

class PortalSpoofer {
    constructor(container) {
        this.container = container;
        this.currentMac = null;
        this.targetMac = null;
        this.targetIp = null;
        this.targetPackets = 0;
        this.targetConfidence = 0;
        this.options = {
            renew_dhcp: true,
            test_internet: true,
        };
        this.log = [];
        this.spoofing = false;
    }

    render(currentMacInfo) {
        if (currentMacInfo) {
            this.currentMac = currentMacInfo;
        }
        this._draw();
    }

    setTarget(mac, ip, packets, confidence) {
        this.targetMac = mac;
        this.targetIp = ip || '';
        this.targetPackets = packets || 0;
        this.targetConfidence = confidence || 0;
        this._draw();
    }

    addLog(message, success) {
        const time = new Date().toLocaleTimeString('fr-FR');
        this.log.push({ time, message, success });
        this._appendLog(time, message, success);
    }

    clearLog() {
        this.log = [];
        const logEl = document.getElementById('portal-spoof-log');
        if (logEl) logEl.innerHTML = '';
    }

    setSpoofing(spoofing) {
        this.spoofing = spoofing;
        const btn = document.getElementById('portal-spoof-btn');
        const restoreBtn = document.getElementById('portal-restore-btn');
        if (btn) {
            btn.disabled = spoofing || !this.targetMac;
            btn.textContent = spoofing ? '⏳ En cours...' : '▶ SPOOF MAC';
        }
        if (restoreBtn) {
            restoreBtn.disabled = spoofing;
        }
    }

    _draw() {
        const cur = this.currentMac;
        const curMac = cur ? cur.mac : '—';
        const curInterface = cur ? (cur.interface || '—') : '—';
        const isSpoofed = cur && cur.is_spoofed;
        const curStatus = isSpoofed
            ? '🟡 MAC spoofée'
            : this.targetMac
                ? '🔴 Bloqué par le portail'
                : '⚪ Statut inconnu';

        const targetSection = this.targetMac ? `
            <div class="portal-spoof-card">
                <div class="portal-spoof-card-title">MAC CIBLE (client autorisé)</div>
                <div class="portal-spoof-mac">${this.targetMac}</div>
                <div class="portal-spoof-card-details">
                    ${this.targetIp ? `IP : ${this.targetIp} · ` : ''}${this.targetPackets} paquets détectés
                </div>
                ${this.targetConfidence > 0 ? `
                    <div class="portal-spoof-confidence">
                        <span>Confiance :</span>
                        <div class="portal-confidence-bar">
                            <div class="portal-confidence-fill" style="width:${Math.round(this.targetConfidence * 100)}%"></div>
                        </div>
                        <span>${Math.round(this.targetConfidence * 100)}%</span>
                    </div>
                ` : ''}
            </div>

            ${this.targetConfidence < 0.5 || this.targetPackets < 20 ? `
                <div class="portal-warnings">
                    <div class="portal-warning-title">⚠ AVERTISSEMENTS</div>
                    ${this.targetConfidence < 0.5 ? '<div class="portal-warning-item">• Confiance faible — peu de trafic observé</div>' : ''}
                    <div class="portal-warning-item">• Le client cible est peut-être EN LIGNE — conflit MAC possible</div>
                    <div class="portal-warning-item">• L'appareil cible pourrait perdre sa connexion</div>
                </div>
            ` : ''}
        ` : `
            <div class="portal-spoof-empty">
                <p class="text-muted">Aucune MAC cible sélectionnée.</p>
                <p class="text-muted">Allez dans l'onglet <strong>Clients</strong> et cliquez sur "Utiliser cette MAC →" sur un client autorisé.</p>
            </div>
        `;

        this.container.innerHTML = `
            <div class="portal-spoofer-section">
                <h3 class="portal-section-title">MAC SPOOFER</h3>

                <!-- MAC actuelle -->
                <div class="portal-spoof-card">
                    <div class="portal-spoof-card-title">TA MAC ACTUELLE</div>
                    <div class="portal-spoof-mac">${curMac}</div>
                    <div class="portal-spoof-card-details">Interface : ${curInterface}</div>
                    <div class="portal-spoof-status">${curStatus}</div>
                </div>

                <!-- MAC cible -->
                ${targetSection}

                <!-- Options -->
                ${this.targetMac ? `
                    <div class="portal-spoof-options">
                        <div class="portal-option-title">OPTIONS</div>
                        <label class="portal-option-row">
                            <input type="checkbox" id="opt-renew-dhcp" ${this.options.renew_dhcp ? 'checked' : ''}>
                            <span>Renouveler l'IP après le changement (DHCP)</span>
                        </label>
                        <label class="portal-option-row">
                            <input type="checkbox" id="opt-test-internet" ${this.options.test_internet ? 'checked' : ''}>
                            <span>Tester l'accès Internet automatiquement</span>
                        </label>
                    </div>

                    <div class="portal-spoof-actions">
                        <button class="btn btn-primary btn-lg" id="portal-spoof-btn" ${this.spoofing ? 'disabled' : ''}>
                            ${this.spoofing ? '⏳ En cours...' : '▶ SPOOF MAC'}
                        </button>
                        <button class="btn btn-outline" id="portal-restore-btn" ${this.spoofing ? 'disabled' : ''}>
                            ↩ RESTAURER ORIGINAL
                        </button>
                    </div>
                ` : ''}

                <!-- Log -->
                <div class="portal-spoof-log-section">
                    <div class="portal-log-title">LOG</div>
                    <div class="portal-spoof-log" id="portal-spoof-log">
                        ${this.log.map(l => this._logLine(l.time, l.message, l.success)).join('')}
                    </div>
                </div>
            </div>
        `;

        // Événements
        this._attachEvents();
    }

    _attachEvents() {
        const spoofBtn = document.getElementById('portal-spoof-btn');
        const restoreBtn = document.getElementById('portal-restore-btn');
        const renewDhcp = document.getElementById('opt-renew-dhcp');
        const testInternet = document.getElementById('opt-test-internet');

        if (spoofBtn) {
            spoofBtn.addEventListener('click', () => this._doSpoof());
        }

        if (restoreBtn) {
            restoreBtn.addEventListener('click', () => this._doRestore());
        }

        if (renewDhcp) {
            renewDhcp.addEventListener('change', (e) => {
                this.options.renew_dhcp = e.target.checked;
            });
        }

        if (testInternet) {
            testInternet.addEventListener('change', (e) => {
                this.options.test_internet = e.target.checked;
            });
        }
    }

    async _doSpoof() {
        if (!this.targetMac || this.spoofing) return;

        this.clearLog();
        this.setSpoofing(true);
        this.addLog('Démarrage du MAC spoofing...', true);

        try {
            const resp = await api.post('/portal/mac/spoof', {
                target_mac: this.targetMac,
                renew_dhcp: this.options.renew_dhcp,
                test_internet: this.options.test_internet,
            });

            if (resp.error) {
                this.addLog(`Erreur : ${resp.error}`, false);
                this.setSpoofing(false);
            }
            // Les événements WebSocket portal:spoof_progress et portal:spoof_result
            // mettront à jour le log et arrêteront le spoofing

        } catch (e) {
            this.addLog(`Erreur réseau : ${e.message}`, false);
            this.setSpoofing(false);
        }
    }

    async _doRestore() {
        if (this.spoofing) return;

        this.setSpoofing(true);
        this.addLog('Restauration de la MAC originale...', true);

        try {
            const resp = await api.post('/portal/mac/restore', {});
            if (resp.success) {
                this.addLog(`MAC restaurée : ${resp.restored_mac}`, true);
                // Rafraîchir la MAC actuelle
                const macInfo = await api.get('/portal/mac/current');
                this.render(macInfo);
            } else {
                this.addLog(`Erreur : ${resp.error}`, false);
            }
        } catch (e) {
            this.addLog(`Erreur : ${e.message}`, false);
        }

        this.setSpoofing(false);
    }

    _logLine(time, message, success) {
        const cls = success === false ? 'log-error' : success === true ? 'log-success' : '';
        return `<div class="portal-log-line ${cls}"><span class="log-time">${time}</span> ${message}</div>`;
    }

    _appendLog(time, message, success) {
        const logEl = document.getElementById('portal-spoof-log');
        if (!logEl) return;

        const line = document.createElement('div');
        const cls = success === false ? 'log-error' : success === true ? 'log-success' : '';
        line.className = `portal-log-line ${cls}`;
        line.innerHTML = `<span class="log-time">${time}</span> ${message}`;
        logEl.appendChild(line);
        logEl.scrollTop = logEl.scrollHeight;
    }
}

window.PortalSpoofer = PortalSpoofer;
