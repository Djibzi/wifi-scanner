// progress-bar.js — Barre de progression

class ProgressBar {
    static render(percent, large = false) {
        const cls = large ? 'progress-bar progress-bar-lg' : 'progress-bar';
        return `
            <div class="${cls}">
                <div class="progress-fill" style="width: ${percent}%"></div>
            </div>
        `;
    }

    static update(container, percent) {
        const fill = container.querySelector('.progress-fill');
        if (fill) {
            fill.style.width = `${percent}%`;
        }
    }
}

window.ProgressBar = ProgressBar;
