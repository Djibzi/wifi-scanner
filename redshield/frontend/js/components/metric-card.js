// metric-card.js — Composant carte métrique

class MetricCard {
    static render(label, value, sub = '', variant = '') {
        const cls = variant ? `metric-card card-${variant}` : 'metric-card';
        return `
            <div class="${cls}">
                <div class="metric-label">${label}</div>
                <div class="metric-value">${value}</div>
                ${sub ? `<div class="metric-sub">${sub}</div>` : ''}
            </div>
        `;
    }
}

window.MetricCard = MetricCard;
