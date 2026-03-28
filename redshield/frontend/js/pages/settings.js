// settings.js — Page Paramètres

class SettingsPage {
    constructor() {
        this.container = null;
        this.settings = {};
    }

    mount(container) {
        this.container = container;
        this._loadSettings();
    }

    unmount() {
        this.container = null;
    }

    async _loadSettings() {
        try {
            this.settings = await api.getSettings() || {};
        } catch {
            this.settings = {};
        }
        this._render();
    }

    async _save(key, value) {
        this.settings[key] = value;
        try {
            await api.updateSettings({ [key]: value });
            Toast.success('Sauvegardé', `${key} mis à jour`);
        } catch (e) {
            Toast.error('Erreur', e.message);
        }
    }

    _render() {
        if (!this.container) return;
        window.settingsPage = this;

        const s = this.settings;

        this.container.innerHTML = `
            <!-- Scan -->
            <div class="settings-section">
                <h3>Configuration du scan</h3>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Mode par défaut</div>
                        <div class="label-desc">Détermine le nombre de ports scannés</div>
                    </div>
                    <div class="setting-control">
                        <select class="select" onchange="settingsPage._save('scan_mode', this.value)">
                            <option value="quick" ${s.scan_mode === 'quick' ? 'selected' : ''}>Rapide</option>
                            <option value="normal" ${s.scan_mode === 'normal' ? 'selected' : ''}>Normal</option>
                            <option value="full" ${s.scan_mode === 'full' ? 'selected' : ''}>Complet</option>
                        </select>
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Timeout (secondes)</div>
                        <div class="label-desc">Délai d'attente par connexion</div>
                    </div>
                    <div class="setting-control">
                        <input class="input input-number" type="number" min="0.1" max="10" step="0.1"
                            value="${s.timeout || 0.5}"
                            onchange="settingsPage._save('timeout', parseFloat(this.value))">
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Threads</div>
                        <div class="label-desc">Nombre de connexions parallèles</div>
                    </div>
                    <div class="setting-control">
                        <input class="input input-number" type="number" min="10" max="1000" step="10"
                            value="${s.threads || 200}"
                            onchange="settingsPage._save('threads', parseInt(this.value))">
                    </div>
                </div>
            </div>

            <!-- Credentials -->
            <div class="settings-section">
                <h3>Test d'identifiants</h3>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Tentatives max</div>
                        <div class="label-desc">Nombre max de tentatives par service</div>
                    </div>
                    <div class="setting-control">
                        <input class="input input-number" type="number" min="1" max="20"
                            value="${s.max_credential_attempts || 3}"
                            onchange="settingsPage._save('max_credential_attempts', parseInt(this.value))">
                    </div>
                </div>
            </div>

            <!-- Interface -->
            <div class="settings-section">
                <h3>Interface</h3>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Thème</div>
                        <div class="label-desc">Mode sombre ou clair</div>
                    </div>
                    <div class="setting-control">
                        ${ThemeToggle.render()}
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Notifications</div>
                        <div class="label-desc">Afficher les notifications toast</div>
                    </div>
                    <div class="setting-control">
                        <label class="toggle">
                            <input type="checkbox" ${s.notifications !== false ? 'checked' : ''}
                                onchange="settingsPage._save('notifications', this.checked)">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
            </div>

            <!-- Réseau -->
            <div class="settings-section">
                <h3>Réseau</h3>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Mode promiscuous</div>
                        <div class="label-desc">Capturer tout le trafic (nécessite admin)</div>
                    </div>
                    <div class="setting-control">
                        <label class="toggle">
                            <input type="checkbox" ${s.promiscuous_mode ? 'checked' : ''}
                                onchange="settingsPage._save('promiscuous_mode', this.checked)">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
            </div>

            <!-- Portal -->
            <div class="settings-section">
                <h3>🔓 Portal</h3>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Détection auto du portail</div>
                        <div class="label-desc">Détecter automatiquement les portails captifs lors du scan</div>
                    </div>
                    <div class="setting-control">
                        <label class="toggle">
                            <input type="checkbox" ${s.portal_auto_detect !== false ? 'checked' : ''}
                                onchange="settingsPage._save('portal_auto_detect', this.checked)">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Durée d'écoute du trafic</div>
                        <div class="label-desc">Durée (secondes) pour identifier les clients autorisés</div>
                    </div>
                    <div class="setting-control">
                        <input class="input input-number" type="number" min="5" max="120" step="5"
                            value="${s.portal_listen_duration || 30}"
                            onchange="settingsPage._save('portal_listen_duration', parseInt(this.value))">
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Restauration MAC auto</div>
                        <div class="label-desc">Restaurer la MAC originale à la fermeture de l'application</div>
                    </div>
                    <div class="setting-control">
                        <label class="toggle">
                            <input type="checkbox" ${s.portal_restore_mac !== false ? 'checked' : ''}
                                onchange="settingsPage._save('portal_restore_mac', this.checked)">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
                <div class="setting-row">
                    <div class="setting-label">
                        <div class="label-title">Seuil de confiance client</div>
                        <div class="label-desc">Nombre minimum de paquets vers Internet pour considérer un client comme autorisé</div>
                    </div>
                    <div class="setting-control">
                        <input class="input input-number" type="number" min="1" max="100"
                            value="${s.portal_min_packets || 5}"
                            onchange="settingsPage._save('portal_min_packets', parseInt(this.value))">
                    </div>
                </div>
            </div>

        `;
    }
}

window.SettingsPage = SettingsPage;
