// dashboard.js — Page Dashboard

class DashboardPage {
    constructor() {
        this.container = null;
        this._onHostsChange = null;
        this._onVulnsChange = null;
    }

    mount(container) {
        this.container = container;
        this._render();

        // Écouter les changements du store
        this._onHostsChange = () => this._render();
        this._onVulnsChange = () => this._render();
        store.on('hosts', this._onHostsChange);
        store.on('vulnerabilities', this._onVulnsChange);
    }

    unmount() {
        if (this._onHostsChange) store.off('hosts', this._onHostsChange);
        if (this._onVulnsChange) store.off('vulnerabilities', this._onVulnsChange);
        this.container = null;
    }

    _render() {
        if (!this.container) return;

        const wifi = store.get('wifi');
        const hosts = store.get('hosts') || [];
        const vulns = store.get('vulnerabilities') || [];
        const score = store.get('score') || 0;
        const grade = store.get('grade') || '—';
        const portalDetect = store.get('portalDetect');

        const critCount = vulns.filter(v => v.severity === 'CRITIQUE').length;
        const highCount = vulns.filter(v => v.severity === 'HAUTE').length;

        // Bandeau portail captif
        const portalBanner = portalDetect && portalDetect.detected ? `
            <div class="dashboard-portal-banner" onclick="router.navigate('portal')" style="cursor:pointer">
                <div class="portal-banner-icon">🔓</div>
                <div class="portal-banner-body">
                    <div class="portal-banner-title">PORTAIL CAPTIF DÉTECTÉ</div>
                    <div class="portal-banner-detail">
                        Type : ${portalDetect.type || 'inconnu'}
                        · Statut : ${portalDetect.portal_status === 'down' ? '⚠ En panne' : portalDetect.portal_status || '?'}
                        · Auth : ${portalDetect.auth_method === 'mac_only' ? 'MAC uniquement' : portalDetect.auth_method || '?'}
                    </div>
                </div>
                <button class="btn btn-sm btn-outline" style="flex-shrink:0">Ouvrir le module Portal →</button>
            </div>
        ` : '';

        this.container.innerHTML = `
            ${portalBanner}
            <!-- Bandeau WiFi -->
            <div class="dashboard-wifi-bar">
                <div class="wifi-bar-item">
                    <span class="wifi-bar-label">SSID</span>
                    <span class="wifi-bar-value">${wifi?.ssid || 'Non connecté'}</span>
                </div>
                <div class="wifi-bar-item">
                    <span class="wifi-bar-label">Sécurité</span>
                    <span class="wifi-bar-value">${wifi?.security || '—'}</span>
                </div>
                <div class="wifi-bar-item">
                    <span class="wifi-bar-label">Signal</span>
                    <span class="wifi-bar-value">${wifi?.signal_strength ? wifi.signal_strength + ' dBm' : '—'}</span>
                </div>
                <div class="wifi-bar-item">
                    <span class="wifi-bar-label">Appareils</span>
                    <span class="wifi-bar-value">${hosts.length}</span>
                </div>
            </div>

            <!-- Cartes métriques -->
            <div class="dashboard-metrics">
                ${MetricCard.render('Score de sécurité', score ? `${score}/100` : '—', grade, score >= 75 ? 'low' : score >= 50 ? 'med' : 'crit')}
                ${MetricCard.render('Critiques', critCount, 'vulnérabilités', 'crit')}
                ${MetricCard.render('Hautes', highCount, 'vulnérabilités', 'high')}
                ${MetricCard.render('Appareils', hosts.length, 'sur le réseau')}
            </div>

            <!-- Corps -->
            <div class="dashboard-body">
                <div class="dashboard-threats">
                    <h3>Menaces actives</h3>
                    <div id="dashboard-threats-list">
                        ${vulns.length > 0
                            ? vulns.slice(0, 10).map(v => AlertRow.render(v)).join('')
                            : '<p class="text-muted">Aucune menace détectée. Lancez un scan.</p>'
                        }
                    </div>
                </div>
                <div class="dashboard-charts">
                    <div class="chart-card">
                        <h3>Vulnérabilités par sévérité</h3>
                        <div id="chart-vulns"></div>
                    </div>
                    <div class="chart-card">
                        <h3>Types d'appareils</h3>
                        <div id="chart-devices"></div>
                    </div>
                </div>
            </div>

            <!-- Bouton scan -->
            <div class="dashboard-cta">
                <button class="btn btn-primary btn-lg" onclick="router.navigate('scan')">
                    Lancer un scan
                </button>
            </div>
        `;

        // Dessiner les graphiques
        const vulnChart = document.getElementById('chart-vulns');
        const deviceChart = document.getElementById('chart-devices');
        if (vulnChart) Charts.vulnSummary(vulnChart, vulns);
        if (deviceChart) Charts.deviceTypes(deviceChart, hosts);
    }
}

window.DashboardPage = DashboardPage;
