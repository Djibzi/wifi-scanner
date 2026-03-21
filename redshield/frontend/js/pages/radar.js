// radar.js — Page Radar temps réel
// Visualisation circulaire des appareils selon leur latence et type

class RadarPage {
    constructor() {
        this.container = null;
        this.devices = [];
        this.selectedIp = null;
        this.filters = { risk: null, type: null };
        this.radarRunning = false;
        this._updateInterval = null;
        this._svg = null;
        this._tooltip = null;
        this._size = 600;
        this._cx = 300;
        this._cy = 300;
        this._maxR = 250;
    }

    mount(container) {
        this.container = container;
        this._render();
        this._initRadar();
        this._startUpdates();
    }

    unmount() {
        if (this._updateInterval) {
            clearInterval(this._updateInterval);
            this._updateInterval = null;
        }
        this.container = null;
    }

    getHeaderActions() {
        return '';
    }

    // --- Render principal ---

    _render() {
        if (!this.container) return;

        this.container.innerHTML = `
            <div class="radar-page">
                <!-- Toolbar -->
                <div class="radar-toolbar">
                    <div class="toolbar-group">
                        <button class="btn btn-sm btn-primary" id="radar-toggle">Démarrer</button>
                    </div>
                    <div class="separator"></div>
                    <div class="toolbar-group" id="radar-risk-filters">
                        <button class="radar-filter-btn active" data-risk="">Tous</button>
                        <button class="radar-filter-btn" data-risk="safe">Safe</button>
                        <button class="radar-filter-btn" data-risk="medium">Risque</button>
                        <button class="radar-filter-btn" data-risk="critical">Critique</button>
                    </div>
                    <div class="separator"></div>
                    <div class="toolbar-group" id="radar-type-filters">
                        <button class="radar-filter-btn" data-type="router">Gateway</button>
                        <button class="radar-filter-btn" data-type="desktop">PC</button>
                        <button class="radar-filter-btn" data-type="phone">Mobile</button>
                        <button class="radar-filter-btn" data-type="iot">IoT</button>
                    </div>
                    <div class="radar-status" id="radar-status">
                        <span class="pulse-dot offline" id="radar-dot"></span>
                        <span id="radar-status-text">Inactif</span>
                    </div>
                </div>

                <!-- Radar + Panel -->
                <div class="radar-content">
                    <div class="radar-container" id="radar-container">
                        <!-- SVG injecté ici -->
                    </div>

                    <!-- Panel détail -->
                    <div class="radar-panel" id="radar-panel">
                    </div>

                    <!-- Tooltip -->
                    <div class="radar-tooltip" id="radar-tooltip"></div>
                </div>

                <!-- Footer -->
                <div class="radar-footer">
                    <span class="pulse-dot offline" id="radar-footer-dot"></span>
                    <span id="radar-footer-text">Surveillance inactive</span>
                    <span style="margin-left:auto">
                        <span class="devices-count" id="radar-device-count">0</span> appareils
                    </span>
                </div>
            </div>
        `;

        this._setupEvents();
    }

    _setupEvents() {
        // Toggle start/stop
        const toggleBtn = document.getElementById('radar-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this._toggleRadar());
        }

        // Filtres risque
        document.querySelectorAll('#radar-risk-filters .radar-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('#radar-risk-filters .radar-filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.filters.risk = btn.dataset.risk || null;
                this._applyFilters();
            });
        });

        // Filtres type
        document.querySelectorAll('#radar-type-filters .radar-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                btn.classList.toggle('active');
                const activeTypes = [...document.querySelectorAll('#radar-type-filters .radar-filter-btn.active')]
                    .map(b => b.dataset.type);
                this.filters.type = activeTypes.length > 0 ? activeTypes : null;
                this._applyFilters();
            });
        });
    }

    // --- Initialisation SVG ---

    _initRadar() {
        const container = document.getElementById('radar-container');
        if (!container) return;

        // Taille fixe du viewBox (fiable, responsive via CSS)
        this._size = 600;
        this._cx = 300;
        this._cy = 300;
        this._maxR = 250;

        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', `0 0 ${this._size} ${this._size}`);
        svg.classList.add('radar-svg');
        container.appendChild(svg);
        this._svg = svg;

        // Définitions (gradients, filtres)
        this._createDefs();

        // Couches
        this._layers = {};
        ['grid', 'lines', 'sweep', 'nodes', 'center', 'selection'].forEach(name => {
            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.classList.add(`layer-${name}`);
            svg.appendChild(g);
            this._layers[name] = g;
        });

        this._drawGrid();
        this._drawSweep();
        this._drawCenter();
        this._drawSectorLabels();

        // Clic sur fond = déselection
        svg.addEventListener('click', (e) => {
            if (e.target === svg || e.target.classList.contains('radar-grid-circle') || e.target.classList.contains('radar-grid-line')) {
                this._deselectAll();
            }
        });
    }

    _createDefs() {
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');

        // Gradient du sweep
        const grad = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        grad.id = 'sweep-gradient';
        grad.setAttribute('gradientUnits', 'userSpaceOnUse');
        grad.setAttribute('x1', this._cx.toString());
        grad.setAttribute('y1', this._cy.toString());
        grad.setAttribute('x2', (this._cx + this._maxR).toString());
        grad.setAttribute('y2', this._cy.toString());

        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop1.setAttribute('offset', '0%');
        stop1.setAttribute('stop-color', 'var(--accent, #ef4444)');
        stop1.setAttribute('stop-opacity', '0');
        grad.appendChild(stop1);

        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop2.setAttribute('offset', '100%');
        stop2.setAttribute('stop-color', 'var(--accent, #ef4444)');
        stop2.setAttribute('stop-opacity', '0.3');
        grad.appendChild(stop2);

        defs.appendChild(grad);

        // Glow filter
        const filter = document.createElementNS('http://www.w3.org/2000/svg', 'filter');
        filter.id = 'glow';
        filter.innerHTML = '<feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>';
        defs.appendChild(filter);

        this._svg.appendChild(defs);
    }

    _drawGrid() {
        const g = this._layers.grid;

        // Cercles concentriques (zones de latence)
        const zones = [
            { r: 0.2, label: '< 5ms' },
            { r: 0.45, label: '< 15ms' },
            { r: 0.7, label: '< 50ms' },
            { r: 0.9, label: '< 200ms' },
        ];

        zones.forEach(zone => {
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', this._cx);
            circle.setAttribute('cy', this._cy);
            circle.setAttribute('r', zone.r * this._maxR);
            circle.classList.add('radar-grid-circle');
            g.appendChild(circle);

            // Label de zone
            const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', this._cx + zone.r * this._maxR + 4);
            label.setAttribute('y', this._cy - 3);
            label.classList.add('radar-zone-label');
            label.textContent = zone.label;
            g.appendChild(label);
        });

        // Lignes de quadrant (croix)
        for (let angle = 0; angle < 360; angle += 45) {
            const rad = (angle - 90) * Math.PI / 180;
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', this._cx);
            line.setAttribute('y1', this._cy);
            line.setAttribute('x2', this._cx + this._maxR * 0.95 * Math.cos(rad));
            line.setAttribute('y2', this._cy + this._maxR * 0.95 * Math.sin(rad));
            line.classList.add('radar-grid-line');
            g.appendChild(line);
        }
    }

    _drawSweep() {
        const g = this._layers.sweep;

        // Arc de balayage (cône de 60°)
        const sweepGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        sweepGroup.classList.add('radar-sweep');

        // Créer un path en forme de cône
        const startAngle = -30;
        const endAngle = 0;
        const r = this._maxR * 0.95;

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const startRad = (startAngle - 90) * Math.PI / 180;
        const endRad = (endAngle - 90) * Math.PI / 180;

        const x1 = this._cx + r * Math.cos(startRad);
        const y1 = this._cy + r * Math.sin(startRad);
        const x2 = this._cx + r * Math.cos(endRad);
        const y2 = this._cy + r * Math.sin(endRad);

        const d = `M ${this._cx} ${this._cy} L ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2} Z`;
        path.setAttribute('d', d);
        path.setAttribute('fill', 'url(#sweep-gradient)');
        path.setAttribute('opacity', '0.6');

        sweepGroup.appendChild(path);

        // Ligne d'attaque du sweep
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', this._cx);
        line.setAttribute('y1', this._cy);
        line.setAttribute('x2', this._cx + r * Math.cos(endRad));
        line.setAttribute('y2', this._cy + r * Math.sin(endRad));
        line.setAttribute('stroke', 'var(--accent, #ef4444)');
        line.setAttribute('stroke-width', '1.5');
        line.setAttribute('opacity', '0.8');
        sweepGroup.appendChild(line);

        g.appendChild(sweepGroup);
    }

    _drawCenter() {
        const g = this._layers.center;

        // Cercle décoratif
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('cx', this._cx);
        ring.setAttribute('cy', this._cy);
        ring.setAttribute('r', 12);
        ring.classList.add('radar-center-ring');
        g.appendChild(ring);

        // Point central
        const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        dot.setAttribute('cx', this._cx);
        dot.setAttribute('cy', this._cy);
        dot.setAttribute('r', 4);
        dot.classList.add('radar-center-dot');
        g.appendChild(dot);

        // Label
        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('x', this._cx);
        label.setAttribute('y', this._cy + 24);
        label.classList.add('radar-center-label');
        label.textContent = 'GATEWAY';
        g.appendChild(label);
    }

    _drawSectorLabels() {
        const g = this._layers.grid;
        const labels = [
            { angle: 15, text: 'GATEWAY' },
            { angle: 80, text: 'SERVERS' },
            { angle: 145, text: 'PC' },
            { angle: 195, text: 'MOBILE' },
            { angle: 280, text: 'IoT' },
        ];

        labels.forEach(item => {
            const rad = (item.angle - 90) * Math.PI / 180;
            const r = this._maxR * 1.05;
            const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', this._cx + r * Math.cos(rad));
            label.setAttribute('y', this._cy + r * Math.sin(rad));
            label.setAttribute('text-anchor', 'middle');
            label.classList.add('radar-sector-label');
            label.textContent = item.text;
            g.appendChild(label);
        });
    }

    // --- Gestion des données ---

    async _toggleRadar() {
        const btn = document.getElementById('radar-toggle');
        if (!btn) return;

        try {
            if (this.radarRunning) {
                await fetch('/api/radar/stop', { method: 'POST' });
                this.radarRunning = false;
                btn.textContent = 'Démarrer';
                btn.classList.remove('btn-secondary');
                btn.classList.add('btn-primary');
                this._updateStatus(false);
            } else {
                const resp = await fetch('/api/radar/start', { method: 'POST' });
                const data = await resp.json();
                this.radarRunning = true;
                btn.textContent = 'Arrêter';
                btn.classList.remove('btn-primary');
                btn.classList.add('btn-secondary');
                this._updateStatus(true);
            }
        } catch (e) {
            if (typeof Toast !== 'undefined') {
                Toast.error('Erreur radar', e.message);
            }
        }
    }

    _startUpdates() {
        // Récupérer l'IP locale du PC hôte
        this._localIp = '';
        fetch('/api/radar/status').then(r => r.json()).then(data => {
            this._localIp = data.local_ip || '';
        }).catch(() => {});

        // Polling toutes les 2 secondes
        this._fetchDevices();
        this._updateInterval = setInterval(() => this._fetchDevices(), 2000);

        // Écouter les événements WebSocket
        if (typeof ws !== 'undefined' && ws.socket) {
            ws.socket.on('radar:update', (data) => {
                if (data && data.devices) {
                    this._mergeUpdates(data.devices);
                }
            });
            ws.socket.on('radar:device_added', (data) => {
                this._fetchDevices();
            });
        }

        // Vérifier le statut initial
        fetch('/api/radar/status').then(r => r.json()).then(data => {
            this.radarRunning = data.running;
            this._updateStatus(data.running);
            const btn = document.getElementById('radar-toggle');
            if (btn && data.running) {
                btn.textContent = 'Arrêter';
                btn.classList.remove('btn-primary');
                btn.classList.add('btn-secondary');
            }
        }).catch(() => {});
    }

    async _fetchDevices() {
        try {
            const resp = await fetch('/api/radar/devices');
            const devices = await resp.json();
            this.devices = devices;
            this._updateNodes();
            this._updateDeviceCount();
        } catch (e) {
            // Silencieux
        }
    }

    _mergeUpdates(updates) {
        // Met à jour les latences/positions sans recréer les nœuds
        for (const upd of updates) {
            const dev = this.devices.find(d => d.ip === upd.ip);
            if (dev) {
                dev.latency = upd.latency;
                dev.radius = upd.radius;
                dev.online = upd.status !== 'offline';
                dev.x = upd.x || dev.x;
                dev.y = upd.y || dev.y;
            }
        }
        this._updateNodes();
    }

    // --- Rendu des nœuds ---

    _updateNodes() {
        if (!this._svg || !this._layers) return;

        const lineLayer = this._layers.lines;
        const nodeLayer = this._layers.nodes;

        // Indexer les éléments existants par IP
        if (!this._nodeElements) this._nodeElements = {};
        if (!this._lineElements) this._lineElements = {};

        // Marquer tous comme non-vus
        const seenIps = new Set();

        this.devices.forEach(dev => {
            seenIps.add(dev.ip);
            const pos = this._getPosition(dev);
            const riskClass = this._getRiskClass(dev);
            const isVisible = this._isVisible(dev);

            // Label : hostname si dispo, sinon IP courte
            const isLocal = dev.ip === this._localIp;
            let labelText = dev.hostname || dev.ip;
            // Tronquer si trop long
            if (labelText.length > 16) labelText = labelText.substring(0, 14) + '..';
            if (isLocal) labelText = labelText + ' (moi)';

            // Mettre à jour ou créer la ligne
            let line = this._lineElements[dev.ip];
            if (!line) {
                line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', this._cx);
                line.setAttribute('y1', this._cy);
                line.classList.add('radar-conn-line');
                lineLayer.appendChild(line);
                this._lineElements[dev.ip] = line;
            }
            line.setAttribute('x2', pos.x);
            line.setAttribute('y2', pos.y);
            line.classList.toggle('highlighted', this.selectedIp === dev.ip);
            line.setAttribute('opacity', isVisible ? (this.selectedIp === dev.ip ? '0.5' : '0.15') : '0.03');

            // Mettre à jour ou créer le nœud
            let group = this._nodeElements[dev.ip];
            if (!group) {
                group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                group.classList.add('radar-node');

                // Pulse rings
                const pulse = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                pulse.setAttribute('r', '6');
                pulse.classList.add('pulse-ring');
                pulse.style.display = 'none';
                group.appendChild(pulse);
                group._pulse = pulse;

                const pulse2 = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                pulse2.setAttribute('r', '6');
                pulse2.classList.add('pulse-ring', 'pulse-ring-2');
                pulse2.style.display = 'none';
                group.appendChild(pulse2);
                group._pulse2 = pulse2;

                // Cercle de fond (halo)
                const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                bg.setAttribute('r', '5');
                bg.classList.add('node-bg');
                group.appendChild(bg);
                group._bg = bg;

                // Icône SVG selon le type d'appareil
                const icon = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                icon.classList.add('node-icon');
                icon.setAttribute('transform', 'translate(-7, -7) scale(0.58)');
                icon.innerHTML = this._getDeviceIcon(dev.device_type);
                group.appendChild(icon);
                group._icon = icon;

                // Label nom
                const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                label.setAttribute('y', '16');
                label.classList.add('node-label');
                group.appendChild(label);
                group._label = label;

                // Selection ring
                const selRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                selRing.setAttribute('r', '16');
                selRing.classList.add('selection-ring');
                selRing.style.display = 'none';
                group.appendChild(selRing);
                group._selRing = selRing;

                // Événements
                group.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this._selectDevice(dev);
                });
                group.addEventListener('mouseenter', (e) => this._showTooltip(e, dev));
                group.addEventListener('mouseleave', () => this._hideTooltip());

                nodeLayer.appendChild(group);
                this._nodeElements[dev.ip] = group;
            }

            // Mettre à jour position (transition CSS)
            group.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);

            // Mettre à jour le label
            group._label.textContent = labelText;

            // Mettre à jour la classe de risque + local
            group.classList.remove('risk-safe', 'risk-medium', 'risk-high', 'risk-critical', 'risk-offline', 'risk-local');
            if (isLocal) {
                group.classList.add('risk-local');
            } else {
                group.classList.add(riskClass);
            }

            // Taille du nœud
            group._bg.setAttribute('r', isLocal ? '9' : (riskClass !== 'risk-safe' ? '7' : '5'));

            // Pulsation
            const showPulse = riskClass === 'risk-high' || riskClass === 'risk-critical';
            group._pulse.style.display = showPulse ? '' : 'none';
            group._pulse2.style.display = riskClass === 'risk-critical' ? '' : 'none';

            // Sélection
            group._selRing.style.display = this.selectedIp === dev.ip ? '' : 'none';
            group.classList.toggle('selected', this.selectedIp === dev.ip);
            group.classList.toggle('dimmed', this.selectedIp && this.selectedIp !== dev.ip);

            // Visibilité filtre
            group.setAttribute('opacity', isVisible ? '1' : '0.08');
        });

        // Supprimer les nœuds/lignes d'appareils qui ne sont plus là
        for (const ip of Object.keys(this._nodeElements)) {
            if (!seenIps.has(ip)) {
                this._nodeElements[ip].remove();
                delete this._nodeElements[ip];
            }
        }
        for (const ip of Object.keys(this._lineElements)) {
            if (!seenIps.has(ip)) {
                this._lineElements[ip].remove();
                delete this._lineElements[ip];
            }
        }
    }

    _getPosition(dev) {
        // Convertit les coordonnées polaires en cartésiennes
        // Le backend envoie radius 0-100 (échelle log de la latence)
        // On mappe vers 15%-85% du rayon radar pour que tout soit visible
        const angleDeg = dev.angle || 0;
        const rawRadius = dev.radius || 30;
        const minR = 0.15;
        const maxR = 0.85;
        const radiusNorm = minR + (rawRadius / 100) * (maxR - minR);
        const angleRad = (angleDeg - 90) * Math.PI / 180;
        const r = radiusNorm * this._maxR;

        return {
            x: this._cx + r * Math.cos(angleRad),
            y: this._cy + r * Math.sin(angleRad),
        };
    }

    _getRiskClass(dev) {
        if (!dev.online) return 'risk-offline';
        const vulns = dev.vulns || 0;
        const risk = dev.risk || 0;
        if (risk >= 2 || vulns >= 3) return 'risk-critical';
        if (risk >= 1 || vulns >= 1) return 'risk-high';
        if (vulns > 0) return 'risk-medium';
        return 'risk-safe';
    }

    _getDeviceIcon(deviceType) {
        // Icônes SVG inline par type d'appareil (24x24 viewBox)
        const dt = (deviceType || '').toLowerCase();
        const stroke = 'currentColor';

        // PC / Desktop / Laptop
        if (['desktop', 'pc', 'laptop', 'notebook'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>`;
        }
        // Phone / Mobile
        if (['phone', 'mobile', 'tablet'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>
            </svg>`;
        }
        // Router / Gateway
        if (['router', 'gateway'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <rect x="2" y="14" width="20" height="7" rx="2"/><circle cx="6" cy="17.5" r="1"/><line x1="12" y1="14" x2="12" y2="7"/>
                <circle cx="12" cy="5" r="2"/>
            </svg>`;
        }
        // Server / NAS
        if (['server', 'nas'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
            </svg>`;
        }
        // IoT / Camera
        if (['iot', 'camera'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <circle cx="12" cy="12" r="3"/><path d="M12 2a10 10 0 0 1 10 10"/><path d="M12 6a6 6 0 0 1 6 6"/>
            </svg>`;
        }
        // Printer
        if (['printer'].includes(dt)) {
            return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
                <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>
                <rect x="6" y="14" width="12" height="8"/>
            </svg>`;
        }
        // Unknown / default
        return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="${stroke}" stroke-width="1.8">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>`;
    }

    _isVisible(dev) {
        // Vérifie si le device passe les filtres actifs
        if (this.filters.risk) {
            const rc = this._getRiskClass(dev);
            if (this.filters.risk === 'safe' && rc !== 'risk-safe') return false;
            if (this.filters.risk === 'medium' && rc !== 'risk-medium' && rc !== 'risk-high') return false;
            if (this.filters.risk === 'critical' && rc !== 'risk-critical') return false;
        }
        if (this.filters.type && this.filters.type.length > 0) {
            const dt = (dev.device_type || 'unknown').toLowerCase();
            const match = this.filters.type.some(t => {
                if (t === 'desktop') return ['desktop', 'pc', 'laptop', 'notebook'].includes(dt);
                if (t === 'phone') return ['phone', 'mobile', 'tablet'].includes(dt);
                if (t === 'iot') return ['iot', 'camera', 'printer'].includes(dt);
                if (t === 'router') return ['router', 'gateway'].includes(dt);
                return dt === t;
            });
            if (!match) return false;
        }
        return true;
    }

    _applyFilters() {
        this._updateNodes();
    }

    // --- Tooltip ---

    _showTooltip(event, dev) {
        const tooltip = document.getElementById('radar-tooltip');
        if (!tooltip) return;

        const riskText = this._getRiskText(dev);
        const latencyStr = dev.online ? `${dev.latency}ms` : 'Hors ligne';

        tooltip.innerHTML = `
            <div class="tt-name">${dev.hostname || dev.device_type || 'Appareil'}</div>
            <div class="tt-ip">${dev.ip}</div>
            <div class="tt-latency">Latence : ${latencyStr}</div>
            <div class="tt-risk">${riskText}</div>
        `;

        // Positionner le tooltip
        const containerRect = document.getElementById('radar-container').getBoundingClientRect();
        const x = event.clientX - containerRect.left + 15;
        const y = event.clientY - containerRect.top - 10;

        tooltip.style.left = x + 'px';
        tooltip.style.top = y + 'px';
        tooltip.classList.add('visible');
    }

    _hideTooltip() {
        const tooltip = document.getElementById('radar-tooltip');
        if (tooltip) tooltip.classList.remove('visible');
    }

    _getRiskText(dev) {
        const rc = this._getRiskClass(dev);
        const colors = {
            'risk-safe': '#22c55e',
            'risk-medium': '#f59e0b',
            'risk-high': '#f97316',
            'risk-critical': '#ef4444',
            'risk-offline': '#666',
        };
        const labels = {
            'risk-safe': 'Sécurisé',
            'risk-medium': 'Risque moyen',
            'risk-high': 'Risque élevé',
            'risk-critical': 'Critique',
            'risk-offline': 'Hors ligne',
        };
        return `<span style="color:${colors[rc] || '#666'}">${labels[rc] || 'Inconnu'}</span>`;
    }

    // --- Sélection et panel ---

    _selectDevice(dev) {
        if (this.selectedIp === dev.ip) {
            this._deselectAll();
            return;
        }

        this.selectedIp = dev.ip;
        this._updateNodes();
        this._openPanel(dev);
    }

    _deselectAll() {
        this.selectedIp = null;
        this._updateNodes();
        this._closePanel();
    }

    _openPanel(dev) {
        const panel = document.getElementById('radar-panel');
        if (!panel) return;

        panel.classList.add('open');
        panel.innerHTML = `
            <div class="radar-panel-header">
                <h3>Appareil</h3>
                <button class="radar-panel-close" id="panel-close">&times;</button>
            </div>

            <div class="radar-panel-device">
                <div class="radar-panel-icon">
                    ${typeof DeviceIcons !== 'undefined'
                        ? DeviceIcons.getIconHTML(dev.device_type, '', 32)
                        : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>'
                    }
                </div>
                <div>
                    <div class="radar-panel-name">${dev.hostname || dev.ip}</div>
                    <div class="radar-panel-ip">${dev.ip}</div>
                </div>
            </div>

            <div class="radar-panel-grid">
                <div class="radar-panel-field">
                    <div class="label">MAC</div>
                    <div class="value">${dev.mac || '—'}</div>
                </div>
                <div class="radar-panel-field">
                    <div class="label">Latence</div>
                    <div class="value">${dev.online ? dev.latency + 'ms' : 'Offline'}</div>
                </div>
                <div class="radar-panel-field">
                    <div class="label">Type</div>
                    <div class="value">${dev.device_type || 'Inconnu'}</div>
                </div>
                <div class="radar-panel-field">
                    <div class="label">Status</div>
                    <div class="value" style="color:${dev.online ? '#22c55e' : '#ef4444'}">${dev.online ? 'En ligne' : 'Hors ligne'}</div>
                </div>
            </div>

            <div class="radar-panel-actions">
                <button class="btn btn-sm btn-primary" onclick="router.navigateToHost('${dev.ip}')">Voir détails complets</button>
                <button class="btn btn-sm btn-secondary" id="radar-rescan-btn">Re-ping cet appareil</button>
            </div>
        `;

        // Events du panel
        document.getElementById('panel-close').addEventListener('click', () => this._deselectAll());
        document.getElementById('radar-rescan-btn').addEventListener('click', async () => {
            try {
                const resp = await fetch(`/api/radar/ping/${dev.ip}`, { method: 'POST' });
                const result = await resp.json();
                if (typeof Toast !== 'undefined') {
                    Toast.success('Ping', `${dev.ip} : ${result.latency}ms`);
                }
            } catch (e) {
                if (typeof Toast !== 'undefined') {
                    Toast.error('Ping échoué', e.message);
                }
            }
        });
    }

    _closePanel() {
        const panel = document.getElementById('radar-panel');
        if (panel) {
            panel.classList.remove('open');
            panel.innerHTML = '';
        }
    }

    // --- Status updates ---

    _updateStatus(running) {
        const dot = document.getElementById('radar-dot');
        const footerDot = document.getElementById('radar-footer-dot');
        const text = document.getElementById('radar-status-text');
        const footerText = document.getElementById('radar-footer-text');

        if (dot) dot.classList.toggle('offline', !running);
        if (footerDot) footerDot.classList.toggle('offline', !running);
        if (text) text.textContent = running ? 'Surveillance active' : 'Inactif';
        if (footerText) footerText.textContent = running ? 'Surveillance active' : 'Surveillance inactive';
    }

    _updateDeviceCount() {
        const el = document.getElementById('radar-device-count');
        if (el) el.textContent = this.devices.length;
    }
}

window.RadarPage = RadarPage;
