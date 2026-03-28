// portal-status.js — Composant statut du portail captif (onglet Détection)

class PortalStatus {
    constructor(container) {
        this.container = container;
        this.result = null;
        this.loading = false;
    }

    render(result) {
        this.result = result;
        this._draw();
    }

    setLoading(loading) {
        this.loading = loading;
        if (loading) {
            this.container.innerHTML = `
                <div class="portal-loading">
                    <div class="spinner"></div>
                    <span>Analyse du réseau en cours...</span>
                </div>
            `;
        }
    }

    _draw() {
        if (!this.result) {
            this.container.innerHTML = `
                <div class="portal-empty">
                    <div class="portal-empty-icon">🔓</div>
                    <p>Aucune analyse effectuée.</p>
                    <p class="text-muted">Cliquez sur "Lancer l'analyse" pour détecter un portail captif.</p>
                </div>
            `;
            return;
        }

        const r = this.result;
        const detected = r.detected;
        const statusClass = detected ? 'detected' : 'clear';
        const statusIcon = detected ? '🔴' : '🟢';
        const statusText = detected ? 'DÉTECTÉ' : 'AUCUN';
        const statusSub = detected ? 'Portail actif' : 'Réseau ouvert';

        const portalType = r.type ? this._formatType(r.type) : '—';
        const authMethod = this._formatAuthMethod(r.auth_method);
        const portalStatus = this._formatPortalStatus(r.portal_status);

        const checks = [
            {
                label: 'Accès Internet',
                value: !detected ? '✓ Disponible' : '✗ Bloqué',
                ok: !detected,
            },
            {
                label: 'Redirection HTTP',
                value: r.redirect_url ? `✓ Active vers ${r.redirect_url.substring(0, 40)}${r.redirect_url.length > 40 ? '...' : ''}` : '✗ Non',
                ok: !r.redirect_url,
            },
            {
                label: 'Proxy détecté',
                value: r.proxy ? `✓ ${r.proxy.type} sur port ${r.proxy.port}${r.proxy.version ? ' (' + r.proxy.version + ')' : ''}` : '✗ Non',
                ok: !r.proxy,
            },
            {
                label: 'DNS hijacking',
                value: r.dns_hijack ? '⚠ DNS détourné' : '✗ DNS normal',
                ok: !r.dns_hijack,
            },
            {
                label: 'Type de contrôleur',
                value: portalType,
                ok: null,
            },
            {
                label: 'Auth basée sur',
                value: authMethod,
                ok: r.auth_method === 'credentials',
            },
            {
                label: 'IP du portail',
                value: r.portal_ip || '—',
                ok: null,
            },
            {
                label: 'Port',
                value: r.portal_port || '—',
                ok: null,
            },
        ];

        // Message contextuel
        let contextMsg = '';
        if (detected && r.portal_status === 'down') {
            contextMsg = `
                <div class="portal-alert">
                    <span class="portal-alert-icon">⚠</span>
                    <div>
                        <strong>Le portail semble être en panne.</strong>
                        <p>La page de connexion ne répond pas, mais les règles de firewall sont toujours actives.
                        Des clients précédemment autorisés continuent de naviguer.</p>
                    </div>
                </div>
            `;
        } else if (detected && r.auth_method === 'mac_only') {
            contextMsg = `
                <div class="portal-alert portal-alert-info">
                    <span class="portal-alert-icon">💡</span>
                    <div>
                        <strong>Bypass possible par MAC spoofing.</strong>
                        <p>Ce portail n'utilise que l'adresse MAC pour autoriser les clients.
                        Allez dans l'onglet <strong>Clients</strong> pour identifier un client autorisé,
                        puis dans <strong>Spoofer</strong> pour effectuer le bypass.</p>
                    </div>
                </div>
            `;
        }

        this.container.innerHTML = `
            <div class="portal-detect-section">
                <h3 class="portal-section-title">DÉTECTION DE PORTAIL CAPTIF</h3>

                <!-- Cards statut -->
                <div class="portal-stat-cards">
                    <div class="portal-stat-card portal-stat-${statusClass}">
                        <div class="portal-stat-icon">${statusIcon}</div>
                        <div class="portal-stat-label">STATUT</div>
                        <div class="portal-stat-value">${statusText}</div>
                        <div class="portal-stat-sub">${statusSub}</div>
                    </div>
                    <div class="portal-stat-card">
                        <div class="portal-stat-icon">🔧</div>
                        <div class="portal-stat-label">TYPE</div>
                        <div class="portal-stat-value">${portalType}</div>
                        <div class="portal-stat-sub">${r.proxy ? '+ ' + r.proxy.type : 'Aucun proxy'}</div>
                    </div>
                    <div class="portal-stat-card">
                        <div class="portal-stat-icon">🔑</div>
                        <div class="portal-stat-label">SÉCURITÉ</div>
                        <div class="portal-stat-value">${authMethod}</div>
                        <div class="portal-stat-sub">${r.auth_method === 'mac_only' ? 'Bypass facile' : 'Bypass difficile'}</div>
                    </div>
                </div>

                <!-- Résultats détaillés -->
                <div class="portal-results">
                    <h4>RÉSULTATS DE L'ANALYSE</h4>
                    <div class="portal-check-list">
                        ${checks.map(c => `
                            <div class="portal-check-row">
                                <span class="portal-check-label">${c.label}</span>
                                <span class="portal-check-value ${c.ok === true ? 'text-success' : c.ok === false ? 'text-danger' : 'text-muted'}">${c.value}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                ${contextMsg}
            </div>
        `;
    }

    _formatType(type) {
        const types = {
            nodogsplash: 'Nodogsplash',
            coovachilli: 'CoovaChilli',
            cisco_wlc: 'Cisco WLC',
            unifi: 'UniFi',
            pfsense: 'pfSense',
            openwrt: 'OpenWrt LuCI',
            aruba: 'Aruba ClearPass',
            meraki: 'Cisco Meraki',
            mikrotik: 'MikroTik HotSpot',
            chillispot: 'ChilliSpot',
            unknown: 'Inconnu',
        };
        return types[type] || type;
    }

    _formatAuthMethod(method) {
        const methods = {
            mac_only: 'MAC uniquement',
            credentials: 'Login / Mot de passe',
            social: 'Auth sociale',
            dot1x: '802.1X',
            unknown: 'Inconnu',
        };
        return methods[method] || method || '—';
    }

    _formatPortalStatus(status) {
        const statuses = {
            up: 'En ligne',
            down: 'Hors ligne',
            partial: 'Partiel',
            none: '—',
            unknown: 'Inconnu',
        };
        return statuses[status] || status || '—';
    }
}

window.PortalStatus = PortalStatus;
