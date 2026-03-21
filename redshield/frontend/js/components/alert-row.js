// alert-row.js — Ligne d'alerte dans le dashboard

class AlertRow {
    static render(vuln) {
        const severityMap = {
            'CRITIQUE': 'crit',
            'HAUTE': 'high',
            'MOYENNE': 'med',
            'FAIBLE': 'low',
            'INFO': 'info',
        };
        const cls = severityMap[vuln.severity] || 'info';

        return `
            <div class="alert-card alert-${cls} slide-in">
                <div>
                    ${SeverityBadge.render(vuln.severity)}
                </div>
                <div>
                    <div class="alert-title">${AlertRow._escape(vuln.name)}</div>
                    <div class="alert-desc">
                        ${vuln.host_ip ? vuln.host_ip : 'Réseau'}
                        ${vuln.port ? `:${vuln.port}` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    static _escape(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

window.AlertRow = AlertRow;
