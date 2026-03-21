// report.js — Page Rapport de sécurité

class ReportPage {
    constructor() {
        this.container = null;
    }

    mount(container) {
        this.container = container;
        this._loadReport();
    }

    unmount() {
        this.container = null;
    }

    async _loadReport() {
        if (!this.container) return;

        try {
            const data = await api.getReport();
            if (data && !data.error) {
                this._render(data);
            } else {
                this._renderEmpty();
            }
        } catch {
            this._renderEmpty();
        }
    }

    _renderEmpty() {
        if (!this.container) return;
        this.container.innerHTML = `
            <div style="text-align:center;padding:60px 20px">
                <h2 style="color:var(--text2);margin-bottom:12px">Aucun rapport disponible</h2>
                <p class="text-muted">Lancez un scan pour générer un rapport de sécurité.</p>
                <button class="btn btn-primary btn-lg" style="margin-top:20px" onclick="router.navigate('scan')">
                    Lancer un scan
                </button>
            </div>
        `;
    }

    _render(data) {
        if (!this.container) return;

        const actions = [
            'Corriger les vulnérabilités critiques immédiatement',
            'Traiter les vulnérabilités hautes dans les plus brefs délais',
            'Mettre à jour le firmware du routeur et de tous les appareils',
            'Utiliser WPA3 ou WPA2-AES avec un mot de passe fort (12+ caractères)',
            'Désactiver WPS et UPnP si non nécessaires',
            'Isoler les appareils IoT dans un réseau séparé',
            'Utiliser un DNS sécurisé (1.1.1.1, 8.8.8.8, 9.9.9.9)',
        ];

        const counts = data.vuln_counts || {};

        this.container.innerHTML = `
            <div class="report-header">
                <h2>Rapport de Sécurité</h2>
                <p class="text-muted">Mode : ${data.scan_mode || '—'}</p>
            </div>

            <!-- Score -->
            <div class="report-score-section">
                ${ScoreGauge.render(data.score || 0, data.grade || '—')}
            </div>

            <!-- Résumé -->
            <div class="report-summary-grid">
                <div class="report-summary-item">
                    <div class="summary-number text-crit">${counts.CRITIQUE || 0}</div>
                    <div class="summary-label">Critiques</div>
                </div>
                <div class="report-summary-item">
                    <div class="summary-number text-high">${counts.HAUTE || 0}</div>
                    <div class="summary-label">Hautes</div>
                </div>
                <div class="report-summary-item">
                    <div class="summary-number text-med">${counts.MOYENNE || 0}</div>
                    <div class="summary-label">Moyennes</div>
                </div>
                <div class="report-summary-item">
                    <div class="summary-number">${data.hosts_count || 0}</div>
                    <div class="summary-label">Appareils</div>
                </div>
            </div>

            <!-- Actions prioritaires -->
            <div class="report-section">
                <h2>Actions prioritaires</h2>
                <div class="report-actions">
                    ${actions.map((a, i) => `
                        <div class="report-action-item">
                            <div class="action-number">${i + 1}</div>
                            <div style="font-size:0.9rem">${a}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Export -->
            <div class="report-export-bar">
                <button class="btn btn-primary" onclick="api.exportReport('html')">Export HTML</button>
                <button class="btn btn-secondary" onclick="api.exportReport('md')">Export Markdown</button>
                <button class="btn btn-secondary" onclick="api.exportReport('json')">Export JSON</button>
            </div>
        `;
    }
}

window.ReportPage = ReportPage;
