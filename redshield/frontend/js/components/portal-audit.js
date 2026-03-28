// portal-audit.js — Composant rapport d'audit du portail captif (onglet Audit)

class PortalAudit {
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
                    <span>Audit de sécurité en cours...</span>
                </div>
            `;
        }
    }

    _draw() {
        if (!this.result) {
            this.container.innerHTML = `
                <div class="portal-empty">
                    <div class="portal-empty-icon">🛡</div>
                    <p>Aucun audit effectué.</p>
                    <p class="text-muted">Cliquez sur "Lancer l'audit" pour analyser la sécurité du portail.</p>
                </div>
            `;
            return;
        }

        const r = this.result;
        const scoreColor = r.score >= 75 ? 'audit-grade-good'
            : r.score >= 50 ? 'audit-grade-med'
            : r.score >= 25 ? 'audit-grade-poor'
            : 'audit-grade-crit';

        const gradeName = {
            A: 'Excellent',
            B: 'Bien',
            C: 'Moyen',
            D: 'Faible',
            E: 'Mauvais',
            F: 'Critique',
        }[r.grade] || '';

        const severityIcon = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };
        const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

        const vulns = (r.vulnerabilities || []).sort(
            (a, b) => (severityOrder[a.severity] || 9) - (severityOrder[b.severity] || 9)
        );

        const checksHtml = Object.entries(r.checks || {}).map(([key, val]) => {
            const labels = {
                mac_only_auth: 'Auth MAC uniquement',
                client_isolation: 'Isolation clients',
                https_portal: 'HTTPS sur le portail',
                session_timeout: 'Timeout de session',
                dot1x_available: '802.1X disponible',
                proxy_info_leak: 'Fuite info proxy',
            };

            // Certains checks sont "bons" quand vrais, d'autres quand faux
            const goodWhenTrue = ['client_isolation', 'https_portal', 'session_timeout', 'dot1x_available'];
            const goodWhenFalse = ['mac_only_auth', 'proxy_info_leak'];

            const isGood = goodWhenTrue.includes(key) ? val : !val;
            const icon = isGood ? '✓' : '✗';
            const cls = isGood ? 'check-ok' : 'check-fail';

            return `
                <div class="audit-check-row ${cls}">
                    <span class="audit-check-icon">${icon}</span>
                    <span class="audit-check-label">${labels[key] || key}</span>
                </div>
            `;
        }).join('');

        this.container.innerHTML = `
            <div class="portal-audit-section">
                <h3 class="portal-section-title">AUDIT DE SÉCURITÉ — PORTAIL CAPTIF</h3>

                <!-- Score -->
                <div class="audit-score-row">
                    <div class="audit-score-block ${scoreColor}">
                        <div class="audit-score-number">${r.score}</div>
                        <div class="audit-score-max">/100</div>
                    </div>
                    <div class="audit-grade-block">
                        <div class="audit-grade ${scoreColor}">${r.grade}</div>
                        <div class="audit-grade-name">${gradeName}</div>
                    </div>
                    <div class="audit-counts">
                        ${(r.vuln_count?.CRITICAL || 0) > 0 ? `<div class="audit-count crit">${r.vuln_count.CRITICAL} Critique${r.vuln_count.CRITICAL > 1 ? 's' : ''}</div>` : ''}
                        ${(r.vuln_count?.HIGH || 0) > 0 ? `<div class="audit-count high">${r.vuln_count.HIGH} Haute${r.vuln_count.HIGH > 1 ? 's' : ''}</div>` : ''}
                        ${(r.vuln_count?.MEDIUM || 0) > 0 ? `<div class="audit-count med">${r.vuln_count.MEDIUM} Moyenne${r.vuln_count.MEDIUM > 1 ? 's' : ''}</div>` : ''}
                    </div>
                </div>

                <!-- Checks rapides -->
                ${checksHtml ? `
                    <div class="audit-checks-grid">
                        ${checksHtml}
                    </div>
                ` : ''}

                <!-- Vulnérabilités -->
                ${vulns.length > 0 ? `
                    <div class="audit-vulns">
                        <h4>VULNÉRABILITÉS TROUVÉES</h4>
                        ${vulns.map(v => `
                            <div class="audit-vuln-card severity-${v.severity.toLowerCase()}">
                                <div class="audit-vuln-header">
                                    <span class="audit-vuln-icon">${severityIcon[v.severity] || '⚪'}</span>
                                    <span class="audit-vuln-severity">${v.severity}</span>
                                    <span class="audit-vuln-name">${v.name}</span>
                                    ${v.cvss ? `<span class="audit-vuln-cvss">CVSS ${v.cvss}</span>` : ''}
                                </div>
                                <div class="audit-vuln-desc">${v.description}</div>
                                ${v.remediation ? `
                                    <div class="audit-vuln-fix">
                                        <span class="audit-fix-icon">✏</span>
                                        ${v.remediation}
                                    </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                ` : `
                    <div class="portal-empty">
                        <p>Aucune vulnérabilité détectée.</p>
                    </div>
                `}
            </div>
        `;
    }

    exportReport() {
        if (!this.result) return;

        const r = this.result;
        const lines = [
            '# RAPPORT D\'AUDIT — PORTAIL CAPTIF REDSHIELD',
            `Date : ${new Date().toLocaleString('fr-FR')}`,
            `Score : ${r.score}/100 — Grade ${r.grade}`,
            '',
            '## CHECKS',
        ];

        for (const [key, val] of Object.entries(r.checks || {})) {
            lines.push(`  ${val ? '✓' : '✗'} ${key}`);
        }

        lines.push('', '## VULNÉRABILITÉS');
        for (const v of r.vulnerabilities || []) {
            lines.push(`\n### [${v.severity}] ${v.name}`);
            lines.push(v.description);
            if (v.remediation) lines.push(`\nReméd. : ${v.remediation}`);
        }

        const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `redshield-portal-audit-${Date.now()}.md`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

window.PortalAudit = PortalAudit;
