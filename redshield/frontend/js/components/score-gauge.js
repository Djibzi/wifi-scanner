// score-gauge.js — Jauge circulaire du score de sécurité

class ScoreGauge {
    static render(score, grade) {
        const radius = 65;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (score / 100) * circumference;

        const color = ScoreGauge.getColor(grade);

        return `
            <div class="score-gauge">
                <svg width="160" height="160" viewBox="0 0 160 160">
                    <circle class="gauge-bg" cx="80" cy="80" r="${radius}"/>
                    <circle class="gauge-fill" cx="80" cy="80" r="${radius}"
                        stroke="${color}"
                        stroke-dasharray="${circumference}"
                        stroke-dashoffset="${offset}"/>
                </svg>
                <div class="gauge-text">
                    <div class="gauge-value" style="color:${color}">${score}</div>
                    <div class="gauge-label">${grade}</div>
                </div>
            </div>
        `;
    }

    static getColor(grade) {
        const colors = {
            'A': '#10b981',
            'B': '#34d399',
            'C': '#f59e0b',
            'D': '#f97316',
            'F': '#ef4444',
        };
        return colors[grade] || '#64748b';
    }
}

window.ScoreGauge = ScoreGauge;
