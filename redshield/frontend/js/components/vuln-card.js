// vuln-card.js — Carte de vulnérabilité dépliable

class VulnCard {
    static render(vuln, index) {
        const severityMap = {
            'CRITIQUE': 'crit',
            'HAUTE': 'high',
            'MOYENNE': 'med',
            'FAIBLE': 'low',
            'INFO': 'info',
        };
        const cls = severityMap[vuln.severity] || 'info';

        return `
            <div class="vuln-card vuln-${cls}" id="vuln-${index}">
                <div class="vuln-card-header" onclick="VulnCard.toggle(${index})">
                    <div class="vuln-card-title">
                        ${SeverityBadge.render(vuln.severity)}
                        <span>${VulnCard._escape(vuln.name)}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:12px">
                        <span class="vuln-card-host">${vuln.host_ip || 'Réseau'}${vuln.port ? ':' + vuln.port : ''}</span>
                        <span class="vuln-card-chevron">&#9660;</span>
                    </div>
                </div>
                <div class="vuln-card-body">
                    <div class="vuln-detail-row">
                        <div class="vuln-detail-label">Description</div>
                        <div class="vuln-detail-value">${VulnCard._escape(vuln.description || '')}</div>
                    </div>
                    ${vuln.cve ? `
                    <div class="vuln-detail-row">
                        <div class="vuln-detail-label">CVE</div>
                        <div class="vuln-detail-value mono">${vuln.cve}</div>
                    </div>` : ''}
                    ${vuln.proof ? `
                    <div class="vuln-detail-row">
                        <div class="vuln-detail-label">Preuve</div>
                        <div class="vuln-detail-value mono">${VulnCard._escape(vuln.proof)}</div>
                    </div>` : ''}
                    ${vuln.remediation ? `
                    <div class="vuln-remediation">
                        <strong>Remédiation :</strong> ${VulnCard._escape(vuln.remediation)}
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    static toggle(index) {
        const card = document.getElementById(`vuln-${index}`);
        if (card) {
            card.classList.toggle('expanded');
        }
    }

    static _escape(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

window.VulnCard = VulnCard;
