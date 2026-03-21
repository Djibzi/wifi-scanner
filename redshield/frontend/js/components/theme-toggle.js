// theme-toggle.js — Toggle dark/light avec pastille glissante

class ThemeToggle {
    static render() {
        const isDark = theme.isDark();
        return `
            <label class="toggle">
                <input type="checkbox" ${isDark ? '' : 'checked'} onchange="theme.toggle()">
                <span class="toggle-slider"></span>
            </label>
        `;
    }
}

window.ThemeToggle = ThemeToggle;
