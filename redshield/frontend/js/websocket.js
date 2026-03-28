// websocket.js — Client WebSocket (Socket.IO) pour le temps réel

class WebSocketClient {
    constructor() {
        this.socket = null;
        this.connected = false;
    }

    connect(port) {
        if (this.socket) {
            this.socket.disconnect();
        }

        this.socket = io(`http://127.0.0.1:${port}`, {
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 10,
        });

        this.socket.on('connect', () => {
            this.connected = true;
            store.set('backendOnline', true);
            this._updateStatusBar(true);
        });

        this.socket.on('disconnect', () => {
            this.connected = false;
            store.set('backendOnline', false);
            this._updateStatusBar(false);
        });

        // --- Événements de scan ---

        this.socket.on('scan:started', (data) => {
            store.set('scanning', true);
            store.set('scanProgress', 0);
            Toast.info('Scan démarré', `Mode : ${data.mode}`);
        });

        this.socket.on('scan:progress', (data) => {
            store.set('scanProgress', data.percent);
            store.set('scanModule', data.module);
        });

        this.socket.on('scan:module_complete', (data) => {
            // Notifier la page scan si active
            if (window.scanPage) {
                window.scanPage.onModuleComplete(data);
            }
        });

        this.socket.on('scan:finished', (data) => {
            store.set('scanning', false);
            store.set('scanProgress', 100);
            store.set('score', data.score);
            store.set('grade', data.grade);
            Toast.success('Scan terminé', `Score : ${data.score}/100 (${data.grade})`);
            // Rafraîchir les données
            this._refreshData();
        });

        // --- Événements de découverte ---

        this.socket.on('host:found', (data) => {
            const hosts = store.get('hosts') || [];
            hosts.push(data);
            store.set('hosts', [...hosts]);
        });

        this.socket.on('vuln:found', (data) => {
            const vulns = store.get('vulnerabilities') || [];
            vulns.push(data);
            store.set('vulnerabilities', [...vulns]);
        });

        // --- Trafic ---

        this.socket.on('traffic:stats', (data) => {
            store.set('trafficStats', data);
        });

        this.socket.on('traffic:packet', (data) => {
            store.set('trafficPacket', data);
        });

        this.socket.on('traffic:alert', (data) => {
            Toast.warning('Alerte trafic', data.message || data.name);
        });

        // --- Portail Captif ---

        this.socket.on('portal:detected', (data) => {
            // Stocker dans le store pour le dashboard
            const existing = store.get('portalDetect') || {};
            if (!existing.detected) {
                store.set('portalDetect', { ...data, detected: true });
                Toast.warning('Portail captif', `Type détecté : ${data.type || 'inconnu'}`);
            }
        });

        this.socket.on('portal:client_found', (data) => {
            const clients = store.get('portalClients') || [];
            const existing = clients.find(c => c.mac === data.mac);
            if (!existing) {
                store.set('portalClients', [...clients, data]);
            }
        });

        this.socket.on('portal:clients_update', (data) => {
            // Délégué à la page Portal si active
        });

        this.socket.on('portal:spoof_progress', (data) => {
            // Délégué à la page Portal
        });

        this.socket.on('portal:spoof_result', (data) => {
            // Délégué à la page Portal
        });

        // --- Logs ---

        this.socket.on('log:entry', (data) => {
            if (window.terminalComponent) {
                window.terminalComponent.addLine(data.level, data.message);
            }
        });
    }

    _updateStatusBar(online) {
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('status-text');
        if (dot && text) {
            dot.className = `status-dot ${online ? 'online' : 'offline'}`;
            text.textContent = online ? 'Backend connecté' : 'Backend déconnecté';
        }
    }

    async _refreshData() {
        try {
            const [hosts, vulns, wifi] = await Promise.all([
                api.getHosts(),
                api.getVulnerabilities(),
                api.getWifi(),
            ]);
            store.set('hosts', hosts);
            store.set('vulnerabilities', vulns);
            store.set('wifi', wifi);
        } catch (e) {
            console.error('Erreur rafraîchissement données:', e);
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }
}

window.ws = new WebSocketClient();
