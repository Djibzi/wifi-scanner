// portal-clients.js — Composant liste des clients réseau (onglet Clients)

class PortalClients {
    constructor(container, onSpoof) {
        this.container = container;
        this.onSpoof = onSpoof; // Callback quand "Utiliser cette MAC" est cliqué
        this.clients = [];
        this.listening = false;
        this.listenDuration = 0;
        this.listenStart = null;
        this._timerInterval = null;
    }

    render(clients) {
        this.clients = clients || [];
        this._draw();
    }

    setListening(listening, duration) {
        this.listening = listening;
        this.listenDuration = duration || 0;
        this.listenStart = listening ? Date.now() : null;

        if (this._timerInterval) {
            clearInterval(this._timerInterval);
            this._timerInterval = null;
        }

        if (listening) {
            // Mettre à jour le timer toutes les secondes
            this._timerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - this.listenStart) / 1000);
                const el = document.getElementById('portal-clients-timer');
                if (el) el.textContent = `${elapsed}s`;
            }, 1000);
        }

        this._updateListenStatus();
    }

    destroy() {
        if (this._timerInterval) clearInterval(this._timerInterval);
    }

    _draw() {
        const authorized = this.clients.filter(c => c.status === 'authorized');
        const blocked = this.clients.filter(c => c.status === 'blocked');
        const infra = this.clients.filter(c => c.status === 'infrastructure');

        this.container.innerHTML = `
            <div class="portal-clients-section">
                <div class="portal-clients-header">
                    <h3 class="portal-section-title">CLIENTS RÉSEAU</h3>
                    <div class="portal-listen-status" id="portal-listen-status">
                        <span class="pulse-dot ${this.listening ? 'online' : 'offline'}" id="portal-listen-dot"></span>
                        <span id="portal-listen-text">${this.listening ? 'Écoute active' : 'Inactif'}</span>
                        ${this.listening ? `(<span id="portal-clients-timer">0</span>s)` : ''}
                    </div>
                </div>

                ${this.clients.length === 0 ? `
                    <div class="portal-empty">
                        <p class="text-muted">Aucun client détecté. Cliquez sur "Rafraîchir" pour lancer l'écoute du trafic.</p>
                    </div>
                ` : ''}

                ${authorized.length > 0 ? `
                    <div class="portal-client-group">
                        <div class="portal-client-group-title authorized">
                            ✓ AUTORISÉS (naviguent vers Internet) — ${authorized.length}
                        </div>
                        ${authorized.map(c => this._renderClient(c)).join('')}
                    </div>
                ` : ''}

                ${blocked.length > 0 ? `
                    <div class="portal-client-group">
                        <div class="portal-client-group-title blocked">
                            ✗ BLOQUÉS (pas de trafic Internet) — ${blocked.length}
                        </div>
                        ${blocked.map(c => this._renderClient(c)).join('')}
                    </div>
                ` : ''}

                ${infra.length > 0 ? `
                    <div class="portal-client-group">
                        <div class="portal-client-group-title infra">
                            ◉ INFRASTRUCTURE — ${infra.length}
                        </div>
                        ${infra.map(c => this._renderClient(c)).join('')}
                    </div>
                ` : ''}
            </div>
        `;

        // Attacher les événements
        this.container.querySelectorAll('[data-spoof-mac]').forEach(btn => {
            btn.addEventListener('click', () => {
                const mac = btn.dataset.spoofMac;
                const ip = btn.dataset.spoofIp || '';
                if (this.onSpoof) this.onSpoof(mac, ip);
            });
        });
    }

    _renderClient(c) {
        const isBlocked = c.status === 'blocked';
        const isAuth = c.status === 'authorized';
        const isInfra = c.status === 'infrastructure';

        const statusIcon = isAuth ? '✓' : isBlocked ? '✗' : '◉';
        const statusClass = isAuth ? 'authorized' : isBlocked ? 'blocked' : 'infra';

        const selfBadge = c.is_self ? '<span class="portal-badge portal-badge-self">TOI</span>' : '';
        const gwBadge = c.is_gateway ? '<span class="portal-badge portal-badge-gw">GATEWAY</span>' : '';

        const confidenceBar = isAuth && c.confidence !== undefined ? `
            <div class="portal-confidence">
                <div class="portal-confidence-bar">
                    <div class="portal-confidence-fill" style="width:${Math.round(c.confidence * 100)}%"></div>
                </div>
                <span class="portal-confidence-pct">${Math.round(c.confidence * 100)}%</span>
            </div>
        ` : '';

        const destinations = c.destinations && c.destinations.length > 0
            ? `<div class="portal-client-dests">Trafic vers : ${c.destinations.join(', ')}</div>`
            : '';

        const spoofBtn = isAuth ? `
            <button class="btn btn-sm btn-accent" data-spoof-mac="${c.mac}" data-spoof-ip="${c.ip}">
                Utiliser cette MAC →
            </button>
        ` : '';

        return `
            <div class="portal-client-row ${statusClass}">
                <div class="portal-client-status">${statusIcon}</div>
                <div class="portal-client-info">
                    <div class="portal-client-mac">${c.mac || '—'} ${selfBadge}${gwBadge}</div>
                    <div class="portal-client-details">
                        <span class="portal-client-ip">${c.ip || '—'}</span>
                        ${c.vendor ? `<span class="portal-client-vendor">· ${c.vendor}</span>` : ''}
                        ${c.traffic_count > 0 ? `<span class="portal-client-pkts">· ${c.traffic_count} paquets</span>` : ''}
                    </div>
                    ${destinations}
                    ${confidenceBar}
                </div>
                <div class="portal-client-actions">
                    ${spoofBtn}
                </div>
            </div>
        `;
    }

    _updateListenStatus() {
        const dot = document.getElementById('portal-listen-dot');
        const text = document.getElementById('portal-listen-text');
        if (dot) dot.className = `pulse-dot ${this.listening ? 'online' : 'offline'}`;
        if (text) text.textContent = this.listening ? 'Écoute active' : 'Inactif';
    }
}

window.PortalClients = PortalClients;
