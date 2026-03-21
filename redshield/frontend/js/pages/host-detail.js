// host-detail.js — Page détail d'un appareil

class HostDetailPage {
    constructor() {
        this.container = null;
        this.ip = null;
        this._packetInterval = null;
    }

    mount(container, ip) {
        this.container = container;
        this.ip = ip;
        this._loadHost();
    }

    unmount() {
        if (this._packetInterval) {
            clearInterval(this._packetInterval);
            this._packetInterval = null;
        }
        this.container = null;
    }

    async _loadHost() {
        if (!this.container || !this.ip) return;

        try {
            const host = await api.getHost(this.ip);
            this._render(host);
        } catch (e) {
            this.container.innerHTML = `<p class="text-muted">Erreur : ${e.message}</p>`;
        }
    }

    _render(host) {
        if (!this.container || !host) return;

        const ports = host.open_ports || [];
        const vulns = host.vulnerabilities || [];

        this.container.innerHTML = `
            <!-- Header -->
            <div class="host-detail-header">
                <div class="host-detail-icon">
                    ${typeof DeviceIcons !== 'undefined'
                        ? DeviceIcons.getIconHTML(host.device_type, host.vendor, 40)
                        : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/></svg>'
                    }
                </div>
                <div class="host-detail-info">
                    <h2>${host.hostname || host.ip}</h2>
                    <p class="text-muted">${host.vendor || 'Fabricant inconnu'} ${host.is_gateway ? '(Passerelle)' : ''}</p>
                </div>
                <div style="margin-left:auto;display:flex;gap:8px">
                    <button class="btn btn-sm btn-secondary" onclick="router.navigate('hosts')">Retour</button>
                </div>
            </div>

            <!-- Infos -->
            <div class="host-detail-grid">
                <div class="host-detail-field">
                    <div class="field-label">Adresse IP</div>
                    <div class="field-value mono">${host.ip}</div>
                </div>
                <div class="host-detail-field">
                    <div class="field-label">Adresse MAC</div>
                    <div class="field-value mono">${host.mac || '—'}</div>
                </div>
                <div class="host-detail-field">
                    <div class="field-label">Fabricant</div>
                    <div class="field-value">${host.vendor || '—'}</div>
                </div>
                <div class="host-detail-field">
                    <div class="field-label">Système</div>
                    <div class="field-value">${host.os_guess || '—'}</div>
                </div>
                <div class="host-detail-field">
                    <div class="field-label">Type</div>
                    <div class="field-value">${host.device_type || '—'}</div>
                </div>
                <div class="host-detail-field">
                    <div class="field-label">Hostname</div>
                    <div class="field-value">${host.hostname || '—'}</div>
                </div>
            </div>

            <!-- Ports ouverts -->
            <div class="host-detail-section">
                <h3>Ports ouverts (${ports.length})</h3>
                ${ports.length > 0 ? `
                <table class="data-table">
                    <thead>
                        <tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Banner</th></tr>
                    </thead>
                    <tbody>
                        ${ports.map(p => `
                            <tr>
                                <td class="mono fw-600">${p.number}</td>
                                <td>${p.protocol}</td>
                                <td>${p.service || '—'}</td>
                                <td>${p.version || '—'}</td>
                                <td class="text-dim" style="font-size:0.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis">${this._escape(p.banner || '—')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                ` : '<p class="text-muted">Aucun port ouvert détecté</p>'}
            </div>

            <!-- Vulnérabilités -->
            <div class="host-detail-section">
                <h3>Vulnérabilités (${vulns.length})</h3>
                ${vulns.length > 0
                    ? vulns.map((v, i) => VulnCard.render(v, `host-${i}`)).join('')
                    : '<p class="text-muted">Aucune vulnérabilité détectée</p>'
                }
            </div>

            <!-- Trafic réseau de cet appareil -->
            <div class="host-detail-section">
                <h3>
                    <span>Trafic Réseau</span>
                    <span id="host-pkt-count" style="font-size:0.8rem;color:var(--text-dim);margin-left:8px"></span>
                </h3>
                <div style="display:flex;gap:8px;margin-bottom:10px">
                    <button class="btn btn-sm btn-primary" id="btn-refresh-packets">Rafraîchir</button>
                    <button class="btn btn-sm btn-secondary" id="btn-auto-packets">Auto-refresh: OFF</button>
                    <select id="filter-proto" class="btn btn-sm btn-secondary" style="padding:4px 8px;background:var(--bg-card);color:var(--text);border:1px solid var(--border)">
                        <option value="">Tous protocoles</option>
                        <option value="DNS">DNS</option>
                        <option value="HTTP">HTTP</option>
                        <option value="HTTPS">HTTPS</option>
                        <option value="ARP">ARP</option>
                        <option value="SSH">SSH</option>
                        <option value="FTP">FTP</option>
                    </select>
                </div>
                <div id="host-packets-table" style="max-height:400px;overflow-y:auto;border-radius:8px">
                    <p class="text-muted">Chargement...</p>
                </div>
            </div>
        `;

        // Brancher les boutons paquets
        this._setupPacketControls();
        this._loadPackets();
    }

    _setupPacketControls() {
        const refreshBtn = document.getElementById('btn-refresh-packets');
        const autoBtn = document.getElementById('btn-auto-packets');
        const filterSelect = document.getElementById('filter-proto');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this._loadPackets());
        }

        if (autoBtn) {
            autoBtn.addEventListener('click', () => {
                if (this._packetInterval) {
                    clearInterval(this._packetInterval);
                    this._packetInterval = null;
                    autoBtn.textContent = 'Auto-refresh: OFF';
                    autoBtn.classList.remove('btn-primary');
                    autoBtn.classList.add('btn-secondary');
                } else {
                    this._packetInterval = setInterval(() => this._loadPackets(), 2000);
                    autoBtn.textContent = 'Auto-refresh: ON';
                    autoBtn.classList.remove('btn-secondary');
                    autoBtn.classList.add('btn-primary');
                }
            });
        }

        if (filterSelect) {
            filterSelect.addEventListener('change', () => this._loadPackets());
        }
    }

    async _loadPackets() {
        if (!this.container || !this.ip) return;

        try {
            const resp = await fetch(`/api/traffic/packets/${this.ip}`);
            let packets = await resp.json();

            // Filtre protocole
            const filterSelect = document.getElementById('filter-proto');
            const proto = filterSelect ? filterSelect.value : '';
            if (proto) {
                packets = packets.filter(p => p.protocol === proto);
            }

            this._renderPackets(packets);
        } catch (e) {
            const el = document.getElementById('host-packets-table');
            if (el) el.innerHTML = `<p class="text-muted">Erreur : ${e.message}</p>`;
        }
    }

    _renderPackets(packets) {
        const el = document.getElementById('host-packets-table');
        const countEl = document.getElementById('host-pkt-count');
        if (!el) return;

        if (countEl) countEl.textContent = `(${packets.length} paquets)`;

        if (packets.length === 0) {
            el.innerHTML = '<p class="text-muted">Aucun paquet capturé pour cet appareil. Lancez une capture de trafic d\'abord.</p>';
            return;
        }

        // Afficher les plus récents en premier
        const reversed = [...packets].reverse();

        el.innerHTML = `
            <table class="data-table" style="font-size:0.82rem">
                <thead>
                    <tr>
                        <th style="width:70px">Heure</th>
                        <th>Source</th>
                        <th></th>
                        <th>Destination</th>
                        <th style="width:80px">Protocole</th>
                        <th style="width:60px">Taille</th>
                        <th>Détails</th>
                    </tr>
                </thead>
                <tbody>
                    ${reversed.map(p => {
                        const time = new Date(p.time * 1000);
                        const timeStr = time.toLocaleTimeString('fr-FR');
                        const isSrc = p.src === this.ip;
                        const protoClass = this._getProtoClass(p.protocol);
                        const arrow = isSrc ? '&rarr;' : '&larr;';
                        const arrowColor = isSrc ? '#ef4444' : '#22c55e';

                        return `<tr>
                            <td class="mono text-dim">${timeStr}</td>
                            <td class="mono" style="font-size:0.78rem">${this._escape(p.src_name || p.src)}</td>
                            <td style="color:${arrowColor};font-weight:bold;text-align:center">${arrow}</td>
                            <td class="mono" style="font-size:0.78rem">${this._escape(p.dst_name || p.dst)}</td>
                            <td><span class="proto-badge ${protoClass}">${this._escape(p.protocol)}</span></td>
                            <td class="mono text-dim">${p.size} o</td>
                            <td class="text-dim" style="font-size:0.78rem;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this._escape(p.info || '')}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>
        `;
    }

    _getProtoClass(protocol) {
        const classes = {
            'DNS': 'proto-dns',
            'HTTP': 'proto-http',
            'HTTPS': 'proto-https',
            'ARP': 'proto-arp',
            'SSH': 'proto-ssh',
            'FTP': 'proto-ftp',
            'Telnet': 'proto-telnet',
            'ICMP': 'proto-icmp',
            'mDNS': 'proto-dns',
            'SMB': 'proto-smb',
        };
        return classes[protocol] || 'proto-other';
    }

    _escape(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

window.HostDetailPage = HostDetailPage;
