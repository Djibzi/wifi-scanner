// host-table.js — Tableau des appareils

class HostTable {
    static render(hosts) {
        if (!hosts || hosts.length === 0) {
            return '<p class="text-muted">Aucun appareil découvert. Lancez un scan.</p>';
        }

        let rows = hosts.map(host => {
            const riskClass = HostTable._getRiskClass(host);
            const ports = (host.open_ports || []).map(p => p.number).join(', ') || '—';
            const vulnCount = (host.vulnerabilities || []).length;

            const iconHTML = typeof DeviceIcons !== 'undefined'
                ? DeviceIcons.getIconHTML(host.device_type, host.vendor, 26)
                : '';

            return `
                <tr onclick="router.navigateToHost('${host.ip}')">
                    <td><span class="badge badge-${riskClass}">${HostTable._getRiskLabel(host)}</span></td>
                    <td>
                        <div style="display:flex;align-items:center;gap:8px">
                            ${iconHTML}
                            <div>
                                <div class="fw-600">${host.hostname || host.ip}</div>
                                <div class="text-dim" style="font-size:0.75rem">${host.device_type || ''} ${host.vendor ? '— ' + host.vendor : ''}</div>
                            </div>
                        </div>
                    </td>
                    <td class="mono">${host.ip}</td>
                    <td>${host.os_guess || '—'}</td>
                    <td class="mono" style="font-size:0.8rem">${ports}</td>
                    <td>
                        ${vulnCount > 0
                            ? `<span class="badge badge-${riskClass}">${vulnCount}</span>`
                            : '<span class="text-dim">0</span>'
                        }
                    </td>
                </tr>
            `;
        }).join('');

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Risque</th>
                        <th>Appareil</th>
                        <th>IP</th>
                        <th>OS</th>
                        <th>Ports</th>
                        <th>Vulns</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    static _getRiskClass(host) {
        const vulns = host.vulnerabilities || [];
        if (vulns.some(v => v.severity === 'CRITIQUE')) return 'crit';
        if (vulns.some(v => v.severity === 'HAUTE')) return 'high';
        if (vulns.some(v => v.severity === 'MOYENNE')) return 'med';
        if (vulns.length > 0) return 'low';
        return 'info';
    }

    static _getRiskLabel(host) {
        const vulns = host.vulnerabilities || [];
        if (vulns.some(v => v.severity === 'CRITIQUE')) return 'CRIT';
        if (vulns.some(v => v.severity === 'HAUTE')) return 'HAUT';
        if (vulns.some(v => v.severity === 'MOYENNE')) return 'MOY';
        if (vulns.length > 0) return 'BAS';
        return 'OK';
    }
}

window.HostTable = HostTable;
