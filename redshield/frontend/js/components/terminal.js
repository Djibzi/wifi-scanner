// terminal.js — Terminal de logs en temps réel

class TerminalComponent {
    constructor() {
        this.lines = [];
        this.maxLines = 500;
        this.element = null;
    }

    render() {
        return '<div class="terminal" id="terminal-output"></div>';
    }

    mount() {
        this.element = document.getElementById('terminal-output');
        window.terminalComponent = this;
    }

    addLine(level, message) {
        if (!this.element) return;

        const time = new Date().toLocaleTimeString('fr-FR');
        const levelClass = {
            'info': 'log-info',
            'success': 'log-success',
            'warning': 'log-warning',
            'error': 'log-error',
        }[level] || 'log-info';

        const line = document.createElement('div');
        line.innerHTML = `<span class="log-time">[${time}]</span><span class="${levelClass}">${this._escape(message)}</span>`;

        this.element.appendChild(line);

        // Limiter le nombre de lignes
        while (this.element.childElementCount > this.maxLines) {
            this.element.removeChild(this.element.firstChild);
        }

        // Auto-scroll
        this.element.scrollTop = this.element.scrollHeight;
    }

    clear() {
        if (this.element) {
            this.element.innerHTML = '';
        }
    }

    _escape(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    unmount() {
        window.terminalComponent = null;
        this.element = null;
    }
}

window.TerminalComponent = TerminalComponent;
