// severity-badge.js — Badge de sévérité

class SeverityBadge {
    static render(severity) {
        const map = {
            'CRITIQUE': 'crit',
            'HAUTE': 'high',
            'MOYENNE': 'med',
            'FAIBLE': 'low',
            'INFO': 'info',
        };
        const cls = map[severity] || 'info';
        return `<span class="badge badge-${cls}">${severity}</span>`;
    }
}

window.SeverityBadge = SeverityBadge;
