// network-map.js — Page Carte réseau (D3.js force-directed)

class NetworkMapPage {
    constructor() {
        this.container = null;
    }

    mount(container) {
        this.container = container;
        this._render();
    }

    unmount() {
        this.container = null;
    }

    _render() {
        if (!this.container) return;

        const hosts = store.get('hosts') || [];
        const wifi = store.get('wifi');
        const gateway = wifi?.gateway_ip || '192.168.1.1';

        this.container.innerHTML = `
            <div class="network-map-container" id="network-map-svg">
                ${hosts.length === 0
                    ? '<p class="text-muted" style="padding:40px;text-align:center">Aucun appareil. Lancez un scan pour voir la carte réseau.</p>'
                    : ''
                }
            </div>

            <div class="network-detail-panel" id="network-detail">
                <h3 id="detail-title"></h3>
                <div id="detail-content"></div>
            </div>
        `;

        if (hosts.length > 0) {
            this._drawMap(hosts, gateway);
        }
    }

    _drawMap(hosts, gateway) {
        const container = document.getElementById('network-map-svg');
        if (!container) return;

        const width = container.clientWidth;
        const height = container.clientHeight;

        // Construire les nœuds et liens sans D3 (SVG pur)
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', width);
        svg.setAttribute('height', height);
        svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.min(width, height) * 0.35;

        // Nœud central (routeur)
        const routerHost = { device_type: 'Routeur', vendor: 'Gateway', ip: gateway };
        this._addNode(svg, centerX, centerY, gateway, 'Routeur', 'var(--accent)', 22, routerHost);

        // Appareils en cercle autour du routeur
        hosts.forEach((host, i) => {
            const angle = (2 * Math.PI * i) / hosts.length - Math.PI / 2;
            const x = centerX + radius * Math.cos(angle);
            const y = centerY + radius * Math.sin(angle);

            // Ligne en pointillés vers le routeur
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', centerX);
            line.setAttribute('y1', centerY);
            line.setAttribute('x2', x);
            line.setAttribute('y2', y);
            line.setAttribute('stroke', 'var(--border)');
            line.setAttribute('stroke-dasharray', '4,4');
            line.setAttribute('stroke-width', '1');
            svg.appendChild(line);

            // Couleur selon le risque
            const color = this._getRiskColor(host);
            const label = host.hostname || host.device_type || host.ip;
            const sub = host.vendor || host.ip;
            this._addNode(svg, x, y, label, sub, color, 14, host);
        });

        container.innerHTML = '';
        container.appendChild(svg);

        // Légende
        const legend = document.createElement('div');
        legend.className = 'network-map-legend';
        legend.innerHTML = `
            <div class="legend-item"><div class="legend-dot" style="background:var(--crit)"></div> Critique</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--high)"></div> Haute</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--med)"></div> Moyenne</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--low)"></div> Sûr</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div> Routeur</div>
        `;
        container.appendChild(legend);
    }

    _addNode(svg, x, y, label, sub, color, r, host = null) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.style.cursor = 'pointer';

        // Fond cercle avec couleur de risque
        const bgCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        bgCircle.setAttribute('cx', x);
        bgCircle.setAttribute('cy', y);
        bgCircle.setAttribute('r', r + 8);
        bgCircle.setAttribute('fill', color);
        bgCircle.setAttribute('opacity', '0.15');
        g.appendChild(bgCircle);

        // Bordure colorée
        const borderCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        borderCircle.setAttribute('cx', x);
        borderCircle.setAttribute('cy', y);
        borderCircle.setAttribute('r', r + 8);
        borderCircle.setAttribute('fill', 'none');
        borderCircle.setAttribute('stroke', color);
        borderCircle.setAttribute('stroke-width', '1.5');
        borderCircle.setAttribute('opacity', '0.6');
        g.appendChild(borderCircle);

        // Icône de l'appareil (image SVG)
        const iconSize = r * 2;
        const deviceType = host ? (host.device_type || '') : 'Routeur';
        const vendor = host ? (host.vendor || '') : '';
        const iconSrc = typeof DeviceIcons !== 'undefined'
            ? DeviceIcons.getIcon(deviceType, vendor)
            : 'assets/icons/unknown.svg';

        const img = document.createElementNS('http://www.w3.org/2000/svg', 'image');
        img.setAttribute('href', iconSrc);
        img.setAttribute('x', x - iconSize / 2);
        img.setAttribute('y', y - iconSize / 2);
        img.setAttribute('width', iconSize);
        img.setAttribute('height', iconSize);
        g.appendChild(img);

        // Label
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', x);
        text.setAttribute('y', y + r + 18);
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', 'var(--text2)');
        text.setAttribute('font-size', '11');
        text.setAttribute('font-family', 'JetBrains Mono, monospace');
        text.textContent = label.length > 18 ? label.substring(0, 16) + '...' : label;
        g.appendChild(text);

        if (sub) {
            const subText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            subText.setAttribute('x', x);
            subText.setAttribute('y', y + r + 30);
            subText.setAttribute('text-anchor', 'middle');
            subText.setAttribute('fill', 'var(--text3)');
            subText.setAttribute('font-size', '9');
            subText.textContent = sub.length > 20 ? sub.substring(0, 18) + '...' : sub;
            g.appendChild(subText);
        }

        // Clic pour afficher le détail
        if (host) {
            g.addEventListener('click', () => this._showDetail(host));
        }

        svg.appendChild(g);
    }

    _showDetail(host) {
        const panel = document.getElementById('network-detail');
        const title = document.getElementById('detail-title');
        const content = document.getElementById('detail-content');
        if (!panel || !title || !content) return;

        title.textContent = host.ip;
        content.innerHTML = `
            <div class="detail-row"><span class="detail-label">MAC</span><span>${host.mac || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">Fabricant</span><span>${host.vendor || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">OS</span><span>${host.os_guess || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">Ports</span><span>${(host.open_ports || []).map(p => p.number).join(', ') || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">Vulns</span><span>${(host.vulnerabilities || []).length}</span></div>
            <div style="margin-top:10px">
                <button class="btn btn-sm btn-secondary" onclick="router.navigateToHost('${host.ip}')">Voir détail</button>
            </div>
        `;

        panel.classList.add('visible');
    }

    _getRiskColor(host) {
        const vulns = host.vulnerabilities || [];
        if (vulns.some(v => v.severity === 'CRITIQUE')) return 'var(--crit)';
        if (vulns.some(v => v.severity === 'HAUTE')) return 'var(--high)';
        if (vulns.some(v => v.severity === 'MOYENNE')) return 'var(--med)';
        return 'var(--low)';
    }
}

window.NetworkMapPage = NetworkMapPage;
