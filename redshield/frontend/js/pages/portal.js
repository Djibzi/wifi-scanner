// portal.js — Page Portal (Captive Portal Bypass)
// 4 onglets : Détection, Clients, Spoofer, Audit

class PortalPage {
    constructor() {
        this.container = null;
        this.activeTab = 'detection';
        this._statusComp = null;
        this._clientsComp = null;
        this._spooferComp = null;
        this._auditComp = null;
        this._wsHandlers = [];
    }

    mount(container) {
        this.container = container;
        this._render();
        this._initComponents();
        this._registerWsEvents();

        // Charger les données initiales
        this._loadCurrentMac();
    }

    unmount() {
        // Retirer les handlers WebSocket
        this._wsHandlers.forEach(({ event, fn }) => {
            if (ws.socket) ws.socket.off(event, fn);
        });
        this._wsHandlers = [];

        if (this._clientsComp) this._clientsComp.destroy();
        this.container = null;
    }

    getHeaderActions() {
        return `
            <button class="btn btn-sm btn-outline" onclick="window.portalPage && window.portalPage._refreshTab()">
                ⟳ Rafraîchir
            </button>
        `;
    }

    _render() {
        this.container.innerHTML = `
            <div class="portal-page">
                <!-- Onglets -->
                <div class="portal-tabs">
                    <button class="portal-tab ${this.activeTab === 'detection' ? 'active' : ''}" data-tab="detection">
                        Détection
                    </button>
                    <button class="portal-tab ${this.activeTab === 'clients' ? 'active' : ''}" data-tab="clients">
                        Clients
                        <span class="portal-tab-badge" id="portal-tab-badge-clients"></span>
                    </button>
                    <button class="portal-tab ${this.activeTab === 'spoofer' ? 'active' : ''}" data-tab="spoofer">
                        Spoofer
                    </button>
                    <button class="portal-tab ${this.activeTab === 'audit' ? 'active' : ''}" data-tab="audit">
                        Audit
                    </button>
                </div>

                <!-- Contenu des onglets -->
                <div class="portal-tab-content" id="portal-tab-content">
                </div>

                <!-- Barre d'action contextuelle -->
                <div class="portal-action-bar" id="portal-action-bar">
                    ${this._renderActionBar()}
                </div>
            </div>
        `;

        // Clic sur les onglets
        this.container.querySelectorAll('.portal-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.activeTab = tab.dataset.tab;
                this._switchTab(this.activeTab);
            });
        });

        window.portalPage = this;
    }

    _renderActionBar() {
        switch (this.activeTab) {
            case 'detection':
                return `
                    <button class="btn btn-primary" id="portal-detect-btn">
                        🔍 Lancer l'analyse
                    </button>
                `;
            case 'clients':
                return `
                    <button class="btn btn-primary" id="portal-clients-refresh-btn">
                        ⟳ Rafraîchir (30s)
                    </button>
                    <select class="select" id="portal-listen-duration" style="width:auto">
                        <option value="15">15s</option>
                        <option value="30" selected>30s</option>
                        <option value="60">60s</option>
                        <option value="90">90s</option>
                    </select>
                `;
            case 'audit':
                return `
                    <button class="btn btn-primary" id="portal-audit-btn">
                        🛡 Lancer l'audit
                    </button>
                    <button class="btn btn-outline" id="portal-audit-export-btn" style="display:none">
                        ↓ Exporter le rapport
                    </button>
                `;
            default:
                return '';
        }
    }

    _switchTab(tab) {
        this.activeTab = tab;

        // Mettre à jour les onglets actifs
        this.container.querySelectorAll('.portal-tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tab);
        });

        // Mettre à jour la barre d'action
        const bar = document.getElementById('portal-action-bar');
        if (bar) bar.innerHTML = this._renderActionBar();

        // Monter le contenu de l'onglet
        const content = document.getElementById('portal-tab-content');
        if (!content) return;

        content.innerHTML = '';
        const wrapper = document.createElement('div');
        content.appendChild(wrapper);

        switch (tab) {
            case 'detection':
                this._statusComp = new PortalStatus(wrapper);
                const cachedDetect = store.get('portalDetect');
                this._statusComp.render(cachedDetect);
                this._bindDetectButton();
                break;

            case 'clients':
                this._clientsComp = new PortalClients(wrapper, (mac, ip) => {
                    // Quand "Utiliser cette MAC" est cliqué → aller dans Spoofer
                    this._selectTarget(mac, ip);
                });
                const cachedClients = store.get('portalClients') || [];
                this._clientsComp.render(cachedClients);
                this._bindClientsButton();
                break;

            case 'spoofer':
                this._spooferComp = new PortalSpoofer(wrapper);
                const cachedMac = store.get('portalCurrentMac');
                const cachedTarget = store.get('portalTarget');
                this._spooferComp.render(cachedMac);
                if (cachedTarget) {
                    this._spooferComp.setTarget(
                        cachedTarget.mac,
                        cachedTarget.ip,
                        cachedTarget.packets,
                        cachedTarget.confidence,
                    );
                }
                break;

            case 'audit':
                this._auditComp = new PortalAudit(wrapper);
                const cachedAudit = store.get('portalAudit');
                this._auditComp.render(cachedAudit);
                this._bindAuditButton();
                break;
        }
    }

    _initComponents() {
        this._switchTab(this.activeTab);
    }

    _bindDetectButton() {
        const btn = document.getElementById('portal-detect-btn');
        if (btn) {
            btn.addEventListener('click', () => this._runDetect());
        }
    }

    _bindClientsButton() {
        const btn = document.getElementById('portal-clients-refresh-btn');
        if (btn) {
            btn.addEventListener('click', () => this._refreshClients());
        }
    }

    _bindAuditButton() {
        const auditBtn = document.getElementById('portal-audit-btn');
        if (auditBtn) {
            auditBtn.addEventListener('click', () => this._runAudit());
        }

        const exportBtn = document.getElementById('portal-audit-export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (this._auditComp) this._auditComp.exportReport();
            });
        }
    }

    async _runDetect() {
        const btn = document.getElementById('portal-detect-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = '⏳ Analyse...';
        }

        if (this._statusComp) this._statusComp.setLoading(true);

        try {
            const result = await api.get('/portal/detect');
            store.set('portalDetect', result);

            if (this._statusComp && this.activeTab === 'detection') {
                this._statusComp.render(result);
            }

            // Si portail détecté → montrer une notification
            if (result.detected) {
                Toast.warning(
                    'Portail captif détecté',
                    `Type : ${result.type || 'inconnu'} · Auth : ${result.auth_method || '?'}`,
                );
            } else {
                Toast.success('Réseau ouvert', 'Aucun portail captif détecté');
            }

        } catch (e) {
            Toast.error('Erreur détection', e.message);
            if (this._statusComp) this._statusComp.render(null);
        }

        if (btn) {
            btn.disabled = false;
            btn.textContent = '🔍 Lancer l\'analyse';
        }
    }

    async _refreshClients() {
        const durationSelect = document.getElementById('portal-listen-duration');
        const duration = durationSelect ? parseInt(durationSelect.value) : 30;

        const btn = document.getElementById('portal-clients-refresh-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = '⏳ Écoute...';
        }

        if (this._clientsComp) this._clientsComp.setListening(true, duration);

        try {
            await api.post('/portal/clients/refresh', { duration });

            // Recharger après la durée
            setTimeout(async () => {
                const clients = await api.get('/portal/clients');
                store.set('portalClients', clients);

                if (this._clientsComp && this.activeTab === 'clients') {
                    this._clientsComp.render(clients);
                    this._clientsComp.setListening(false);
                }

                this._updateClientsBadge(clients);

                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '⟳ Rafraîchir';
                }
            }, duration * 1000 + 500);

        } catch (e) {
            Toast.error('Erreur clients', e.message);
            if (this._clientsComp) this._clientsComp.setListening(false);

            if (btn) {
                btn.disabled = false;
                btn.textContent = '⟳ Rafraîchir';
            }
        }
    }

    async _runAudit() {
        const auditBtn = document.getElementById('portal-audit-btn');
        if (auditBtn) {
            auditBtn.disabled = true;
            auditBtn.textContent = '⏳ Audit...';
        }

        if (this._auditComp) this._auditComp.setLoading(true);

        try {
            const result = await api.get('/portal/audit');
            store.set('portalAudit', result);

            if (this._auditComp && this.activeTab === 'audit') {
                this._auditComp.render(result);
            }

            // Afficher le bouton export
            const exportBtn = document.getElementById('portal-audit-export-btn');
            if (exportBtn) exportBtn.style.display = '';

            Toast.info('Audit terminé', `Score : ${result.score}/100 — Grade ${result.grade}`);

        } catch (e) {
            Toast.error('Erreur audit', e.message);
            if (this._auditComp) this._auditComp.render(null);
        }

        if (auditBtn) {
            auditBtn.disabled = false;
            auditBtn.textContent = '🛡 Lancer l\'audit';
        }
    }

    async _loadCurrentMac() {
        try {
            const macInfo = await api.get('/portal/mac/current');
            store.set('portalCurrentMac', macInfo);
            if (this._spooferComp && this.activeTab === 'spoofer') {
                this._spooferComp.render(macInfo);
            }
        } catch (e) {
            // Silencieux — pas bloquant
        }
    }

    _selectTarget(mac, ip, packets, confidence) {
        // Naviguer vers Spoofer et pré-remplir la cible
        store.set('portalTarget', { mac, ip, packets: packets || 0, confidence: confidence || 0 });
        this.activeTab = 'spoofer';
        this._switchTab('spoofer');
        Toast.info('Cible sélectionnée', `MAC ${mac} prête à être spoofée`);
    }

    _updateClientsBadge(clients) {
        const badge = document.getElementById('portal-tab-badge-clients');
        if (!badge) return;
        const authCount = (clients || []).filter(c => c.status === 'authorized').length;
        badge.textContent = authCount > 0 ? authCount : '';
        badge.style.display = authCount > 0 ? '' : 'none';
    }

    _refreshTab() {
        switch (this.activeTab) {
            case 'detection': this._runDetect(); break;
            case 'clients': this._refreshClients(); break;
            case 'audit': this._runAudit(); break;
        }
    }

    _registerWsEvents() {
        if (!ws.socket) return;

        const onDetected = (data) => {
            // Mettre à jour le badge de la sidebar
            const navItem = document.querySelector('.nav-item[data-page="portal"]');
            if (navItem) {
                let badge = navItem.querySelector('.nav-badge');
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'nav-badge';
                    navItem.appendChild(badge);
                }
                badge.textContent = '!';
            }
        };

        const onClientFound = (data) => {
            const clients = store.get('portalClients') || [];
            const existing = clients.find(c => c.mac === data.mac);
            if (!existing) {
                clients.push(data);
                store.set('portalClients', [...clients]);
            }
        };

        const onClientsUpdate = (data) => {
            if (data.clients && this._clientsComp && this.activeTab === 'clients') {
                // Mise à jour partielle du statut
            }
        };

        const onSpoofProgress = (data) => {
            if (this._spooferComp) {
                this._spooferComp.addLog(data.message, data.success);
            }
        };

        const onSpoofResult = (data) => {
            if (this._spooferComp) {
                if (data.success) {
                    this._spooferComp.addLog(
                        `✓ BYPASS RÉUSSI — Nouvelle IP : ${data.new_ip || '?'}`,
                        true,
                    );
                    Toast.success('MAC spoofée !', `Accès Internet : ${data.internet_access ? 'OUI' : 'NON'}`);
                } else {
                    this._spooferComp.addLog(`✗ Échec : ${data.error || 'erreur inconnue'}`, false);
                    Toast.error('Spoof échoué', data.error || 'Erreur inconnue');
                }
                this._spooferComp.setSpoofing(false);
                // Rafraîchir la MAC actuelle
                this._loadCurrentMac();
            }
        };

        ws.socket.on('portal:detected', onDetected);
        ws.socket.on('portal:client_found', onClientFound);
        ws.socket.on('portal:clients_update', onClientsUpdate);
        ws.socket.on('portal:spoof_progress', onSpoofProgress);
        ws.socket.on('portal:spoof_result', onSpoofResult);

        this._wsHandlers = [
            { event: 'portal:detected', fn: onDetected },
            { event: 'portal:client_found', fn: onClientFound },
            { event: 'portal:clients_update', fn: onClientsUpdate },
            { event: 'portal:spoof_progress', fn: onSpoofProgress },
            { event: 'portal:spoof_result', fn: onSpoofResult },
        ];
    }
}

window.PortalPage = PortalPage;
