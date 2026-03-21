// charts.js — Wrapper pour les graphiques (Chart.js optionnel)

class Charts {
    // Graphique en barres simple (sans Chart.js)
    static barChart(container, data, options = {}) {
        const max = Math.max(...data.map(d => d.value), 1);
        const barColor = options.color || 'var(--accent)';

        let html = '<div style="display:flex;flex-direction:column;gap:6px">';

        data.forEach(item => {
            const width = (item.value / max) * 100;
            html += `
                <div style="display:flex;align-items:center;gap:10px">
                    <span style="width:80px;font-size:0.8rem;color:var(--text2);text-align:right">${item.label}</span>
                    <div style="flex:1;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden">
                        <div style="width:${width}%;height:100%;background:${item.color || barColor};border-radius:3px"></div>
                    </div>
                    <span class="mono" style="width:40px;font-size:0.8rem;color:var(--text3);text-align:right">${item.value}</span>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    }

    // Graphique de vulnérabilités par sévérité
    static vulnSummary(container, vulns) {
        const counts = { CRITIQUE: 0, HAUTE: 0, MOYENNE: 0, FAIBLE: 0, INFO: 0 };

        (vulns || []).forEach(v => {
            if (counts[v.severity] !== undefined) {
                counts[v.severity]++;
            }
        });

        const data = [
            { label: 'Critique', value: counts.CRITIQUE, color: 'var(--crit)' },
            { label: 'Haute', value: counts.HAUTE, color: 'var(--high)' },
            { label: 'Moyenne', value: counts.MOYENNE, color: 'var(--med)' },
            { label: 'Faible', value: counts.FAIBLE, color: 'var(--low)' },
            { label: 'Info', value: counts.INFO, color: 'var(--info)' },
        ];

        Charts.barChart(container, data);
    }

    // Répartition des types d'appareils
    static deviceTypes(container, hosts) {
        const types = {};
        (hosts || []).forEach(h => {
            const type = h.device_type || 'Inconnu';
            types[type] = (types[type] || 0) + 1;
        });

        const data = Object.entries(types)
            .map(([label, value]) => ({ label, value }))
            .sort((a, b) => b.value - a.value);

        Charts.barChart(container, data);
    }
}

window.Charts = Charts;
