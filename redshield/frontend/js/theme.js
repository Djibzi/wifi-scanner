// theme.js — Gestionnaire de thème dark/light

class ThemeManager {
    constructor() {
        this.current = localStorage.getItem('theme') || 'dark';
        this.apply();
    }

    toggle() {
        this.current = this.current === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', this.current);
        this.apply();
    }

    apply() {
        document.documentElement.setAttribute('data-theme', this.current);
    }

    isDark() {
        return this.current === 'dark';
    }
}

window.theme = new ThemeManager();
