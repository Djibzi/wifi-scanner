// api.js — Client HTTP vers le backend Flask

class ApiClient {
    constructor() {
        this.baseUrl = '';
    }

    setPort(port) {
        this.baseUrl = `http://127.0.0.1:${port}`;
    }

    async _fetch(path, options = {}) {
        if (!this.baseUrl) return null;

        try {
            const response = await fetch(`${this.baseUrl}${path}`, {
                headers: { 'Content-Type': 'application/json' },
                ...options,
            });

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (err) {
            console.error(`API error [${path}]:`, err);
            throw err;
        }
    }

    // --- Health ---
    async health() {
        return this._fetch('/api/health');
    }

    // --- Scan ---
    async startScan(mode = 'quick', target = '') {
        return this._fetch('/api/scan/start', {
            method: 'POST',
            body: JSON.stringify({ mode, target }),
        });
    }

    async stopScan() {
        return this._fetch('/api/scan/stop', { method: 'POST' });
    }

    async scanStatus() {
        return this._fetch('/api/scan/status');
    }

    // --- WiFi ---
    async getWifi() {
        return this._fetch('/api/wifi');
    }

    // --- Hosts ---
    async getHosts() {
        return this._fetch('/api/hosts');
    }

    async getHost(ip) {
        return this._fetch(`/api/hosts/${ip}`);
    }

    // --- Vulnerabilities ---
    async getVulnerabilities() {
        return this._fetch('/api/vulnerabilities');
    }

    // --- Traffic ---
    async startTraffic() {
        return this._fetch('/api/traffic/start', { method: 'POST' });
    }

    async stopTraffic() {
        return this._fetch('/api/traffic/stop', { method: 'POST' });
    }

    async getTrafficStats() {
        return this._fetch('/api/traffic/stats');
    }

    // --- Report ---
    async getReport() {
        return this._fetch('/api/report');
    }

    async exportReport(format) {
        if (!this.baseUrl) return;
        window.open(`${this.baseUrl}/api/report/export/${format}`, '_blank');
    }

    // --- Settings ---
    async getSettings() {
        return this._fetch('/api/settings');
    }

    async updateSettings(data) {
        return this._fetch('/api/settings', {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    // --- History ---
    async getHistory() {
        return this._fetch('/api/history');
    }

    // --- Helpers génériques pour les routes dynamiques ---
    async get(path) {
        return this._fetch(`/api${path}`);
    }

    async post(path, data) {
        return this._fetch(`/api${path}`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    // --- Portal ---
    async detectPortal() {
        return this._fetch('/api/portal/detect');
    }

    async getPortalClients() {
        return this._fetch('/api/portal/clients');
    }

    async refreshPortalClients(duration) {
        return this._fetch('/api/portal/clients/refresh', {
            method: 'POST',
            body: JSON.stringify({ duration }),
        });
    }

    async getPortalMac() {
        return this._fetch('/api/portal/mac/current');
    }

    async spoofMac(targetMac, renewDhcp, testInternet) {
        return this._fetch('/api/portal/mac/spoof', {
            method: 'POST',
            body: JSON.stringify({
                target_mac: targetMac,
                renew_dhcp: renewDhcp,
                test_internet: testInternet,
            }),
        });
    }

    async restoreMac() {
        return this._fetch('/api/portal/mac/restore', { method: 'POST' });
    }

    async auditPortal() {
        return this._fetch('/api/portal/audit');
    }
}

window.api = new ApiClient();
