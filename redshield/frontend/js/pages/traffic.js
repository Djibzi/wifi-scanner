// traffic.js — Page analyse de trafic temps réel

class TrafficPage {
    constructor() {
        this.container = null;
        this._onStats = null;
        this._onPacket = null;
        this._packets = [];
        this._autoScroll = true;
        this._filter = '';
    }

    mount(container) {
        this.container = container;
        this._packets = [];
        this._render();

        this._onStats = (stats) => this._updateStats(stats);
        this._onPacket = (pkt) => this._addPacket(pkt);
        store.on('trafficStats', this._onStats);
        store.on('trafficPacket', this._onPacket);
    }

    unmount() {
        if (this._onStats) store.off('trafficStats', this._onStats);
        if (this._onPacket) store.off('trafficPacket', this._onPacket);
        this.container = null;
    }

    async _startCapture() {
        try {
            this._packets = [];
            await api.startTraffic();
            store.set('trafficRunning', true);
            Toast.info('Capture démarrée', 'Écoute passive du trafic...');
            this._render();
        } catch (e) {
            Toast.error('Erreur', e.message);
        }
    }

    async _stopCapture() {
        try {
            await api.stopTraffic();
            store.set('trafficRunning', false);
            Toast.info('Capture arrêtée', `${this._packets.length} paquets capturés`);
            this._render();
        } catch (e) {
            Toast.error('Erreur', e.message);
        }
    }

    _addPacket(pkt) {
        // Ajouter le paquet à la liste
        this._packets.push(pkt);
        if (this._packets.length > 500) {
            this._packets = this._packets.slice(-500);
        }

        // Ajouter la ligne au tableau si visible
        const tbody = document.getElementById('packet-tbody');
        if (!tbody) return;

        // Filtrer
        if (this._filter && !this._matchFilter(pkt)) return;

        const row = this._renderPacketRow(pkt, this._packets.length);
        tbody.insertAdjacentHTML('beforeend', row);

        // Auto-scroll
        if (this._autoScroll) {
            const container = document.getElementById('packet-list');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
        }

        // Mettre à jour le compteur
        const countEl = document.getElementById('packet-count');
        if (countEl) countEl.textContent = this._packets.length;
    }

    _renderPacketRow(pkt, index) {
        const protoClass = this._getProtoClass(pkt.protocol);
        const srcName = pkt.src_name || pkt.src;
        const dstName = pkt.dst_name || pkt.dst;

        return `
            <tr class="packet-row ${protoClass}">
                <td class="mono pkt-num">${index}</td>
                <td class="pkt-src" title="${pkt.src}">
                    <span class="pkt-name">${this._shortName(srcName)}</span>
                </td>
                <td class="pkt-arrow">→</td>
                <td class="pkt-dst" title="${pkt.dst}">
                    <span class="pkt-name">${this._shortName(dstName)}</span>
                </td>
                <td><span class="pkt-proto badge-${protoClass}">${pkt.protocol}</span></td>
                <td class="mono pkt-size">${pkt.size}</td>
                <td class="pkt-info">${pkt.info || ''}</td>
            </tr>
        `;
    }

    _shortName(name) {
        if (!name) return '?';
        if (name.length > 22) return name.substring(0, 20) + '...';
        return name;
    }

    _getProtoClass(proto) {
        if (!proto) return 'other';
        const p = proto.toUpperCase();
        if (p === 'DNS' || p === 'MDNS') return 'dns';
        if (p === 'HTTP' || p === 'HTTP-ALT') return 'http';
        if (p === 'HTTPS' || p === 'HTTPS-ALT') return 'tls';
        if (p === 'ARP') return 'arp';
        if (p === 'ICMP') return 'icmp';
        if (p === 'SSH') return 'tls';
        if (p === 'SMB' || p === 'NETBIOS' || p === 'NETBIOS-SSN') return 'smb';
        if (p === 'FTP' || p === 'TELNET') return 'danger';
        if (p === 'DHCP' || p === 'NTP') return 'sys';
        return 'other';
    }

    _matchFilter(pkt) {
        if (!this._filter) return true;
        const q = this._filter.toLowerCase();
        return (
            (pkt.src || '').toLowerCase().includes(q) ||
            (pkt.dst || '').toLowerCase().includes(q) ||
            (pkt.src_name || '').toLowerCase().includes(q) ||
            (pkt.dst_name || '').toLowerCase().includes(q) ||
            (pkt.protocol || '').toLowerCase().includes(q) ||
            (pkt.info || '').toLowerCase().includes(q)
        );
    }

    _onFilterChange(value) {
        this._filter = value;
        // Re-render le tableau filtré
        const tbody = document.getElementById('packet-tbody');
        if (!tbody) return;
        const filtered = this._filter
            ? this._packets.filter(p => this._matchFilter(p))
            : this._packets;
        tbody.innerHTML = filtered.map((p, i) => this._renderPacketRow(p, i + 1)).join('');
    }

    _toggleAutoScroll() {
        this._autoScroll = !this._autoScroll;
        const btn = document.getElementById('autoscroll-btn');
        if (btn) {
            btn.classList.toggle('active', this._autoScroll);
            btn.textContent = this._autoScroll ? 'Auto-scroll ON' : 'Auto-scroll OFF';
        }
    }

    _clearPackets() {
        this._packets = [];
        const tbody = document.getElementById('packet-tbody');
        if (tbody) tbody.innerHTML = '';
        const countEl = document.getElementById('packet-count');
        if (countEl) countEl.textContent = '0';
    }

    _updateStats(stats) {
        if (!stats) return;

        const packetsEl = document.getElementById('traffic-packets');
        const bytesEl = document.getElementById('traffic-bytes');
        const arpEl = document.getElementById('traffic-arp');
        const protosEl = document.getElementById('traffic-protos');
        const talkersEl = document.getElementById('traffic-talkers');
        const protoListEl = document.getElementById('traffic-proto-list');

        if (packetsEl) packetsEl.textContent = stats.packets || 0;
        if (bytesEl) bytesEl.textContent = this._formatBytes(stats.bytes || 0);
        if (arpEl) arpEl.textContent = stats.arp_anomalies || 0;

        if (protosEl && stats.unencrypted_protocols) {
            protosEl.innerHTML = stats.unencrypted_protocols.length > 0
                ? stats.unencrypted_protocols.map(p =>
                    `<span class="badge badge-med">${p}</span>`
                ).join(' ')
                : '<span class="text-muted">Aucun</span>';
        }

        // Top talkers avec noms
        if (talkersEl && stats.top_talkers) {
            const maxBytes = stats.top_talkers.length > 0 ? stats.top_talkers[0][1] : 1;
            talkersEl.innerHTML = stats.top_talkers.slice(0, 8).map(([name, bytes, ip]) => `
                <div class="talker-row">
                    <span class="talker-name" title="${ip}">${this._shortName(name)}</span>
                    <div class="talker-bar">
                        <div class="talker-fill" style="width:${Math.max(3, (bytes / maxBytes) * 100)}%"></div>
                    </div>
                    <span class="talker-bytes mono">${this._formatBytes(bytes)}</span>
                </div>
            `).join('');
        }

        // Protocoles breakdown
        if (protoListEl && stats.protocols) {
            const sorted = Object.entries(stats.protocols).sort((a, b) => b[1] - a[1]);
            const total = sorted.reduce((s, [, c]) => s + c, 0) || 1;
            protoListEl.innerHTML = sorted.slice(0, 8).map(([proto, count]) => `
                <div class="proto-row">
                    <span class="pkt-proto badge-${this._getProtoClass(proto)}">${proto}</span>
                    <div class="talker-bar">
                        <div class="talker-fill" style="width:${(count / total) * 100}%"></div>
                    </div>
                    <span class="mono">${count}</span>
                </div>
            `).join('');
        }
    }

    _formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' o';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' Ko';
        return (bytes / 1048576).toFixed(1) + ' Mo';
    }

    _render() {
        if (!this.container) return;
        window.trafficPage = this;

        const running = store.get('trafficRunning');

        this.container.innerHTML = `
            <div class="traffic-controls">
                ${running
                    ? '<button class="btn btn-danger" onclick="trafficPage._stopCapture()">Arrêter la capture</button>'
                    : '<button class="btn btn-primary" onclick="trafficPage._startCapture()">Démarrer la capture</button>'
                }
                <button class="btn btn-sm btn-secondary" onclick="trafficPage._clearPackets()">Effacer</button>
                <button class="btn btn-sm btn-secondary ${this._autoScroll ? 'active' : ''}" id="autoscroll-btn"
                    onclick="trafficPage._toggleAutoScroll()">${this._autoScroll ? 'Auto-scroll ON' : 'Auto-scroll OFF'}</button>
                <input class="input traffic-filter" placeholder="Filtrer (IP, protocole, nom...)"
                    oninput="trafficPage._onFilterChange(this.value)" value="${this._filter}">
                ${running ? '<div class="spinner"></div>' : ''}
                <span class="text-muted"><span id="packet-count">${this._packets.length}</span> paquets</span>
            </div>

            <!-- Tableau des paquets -->
            <div class="packet-list" id="packet-list">
                <table class="packet-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Source</th>
                            <th></th>
                            <th>Destination</th>
                            <th>Protocole</th>
                            <th>Taille</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody id="packet-tbody">
                        ${this._packets.map((p, i) => this._renderPacketRow(p, i + 1)).join('')}
                    </tbody>
                </table>
            </div>

            <!-- Stats en bas -->
            <div class="traffic-stats-grid">
                <div class="traffic-stat-card">
                    <h4>Top appareils</h4>
                    <div id="traffic-talkers">
                        <p class="text-muted">${running ? 'En attente...' : 'Démarrez la capture'}</p>
                    </div>
                </div>
                <div class="traffic-stat-card">
                    <h4>Protocoles</h4>
                    <div id="traffic-proto-list">
                        <p class="text-muted">${running ? 'En attente...' : ''}</p>
                    </div>
                </div>
                <div class="traffic-stat-card traffic-stat-numbers">
                    <div>
                        <span class="text-dim">Paquets</span>
                        <span class="fw-600 mono" id="traffic-packets">0</span>
                    </div>
                    <div>
                        <span class="text-dim">Volume</span>
                        <span class="fw-600 mono" id="traffic-bytes">0 o</span>
                    </div>
                    <div>
                        <span class="text-dim">Anomalies ARP</span>
                        <span class="fw-600 mono" id="traffic-arp">0</span>
                    </div>
                    <div>
                        <span class="text-dim">Non chiffrés</span>
                        <div id="traffic-protos" style="margin-top:4px">
                            <span class="text-muted">Aucun</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
}

window.TrafficPage = TrafficPage;
