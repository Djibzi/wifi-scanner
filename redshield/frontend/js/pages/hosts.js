// hosts.js — Page liste des appareils

class HostsPage {
    constructor() {
        this.container = null;
        this.filter = '';
        this._onHostsChange = null;
    }

    mount(container) {
        this.container = container;
        this._render();

        this._onHostsChange = () => this._render();
        store.on('hosts', this._onHostsChange);
    }

    unmount() {
        if (this._onHostsChange) store.off('hosts', this._onHostsChange);
        this.container = null;
    }

    _render() {
        if (!this.container) return;

        const hosts = store.get('hosts') || [];
        const filtered = this._applyFilter(hosts);

        this.container.innerHTML = `
            <div class="hosts-toolbar">
                <input class="input hosts-search" id="hosts-search"
                    placeholder="Rechercher (IP, nom, fabricant...)"
                    value="${this.filter}"
                    oninput="hostsPage._onSearch(this.value)">
                <div class="hosts-filters">
                    <span class="filter-chip ${this.filter === '' ? 'active' : ''}"
                        onclick="hostsPage._setFilter('')">Tous (${hosts.length})</span>
                    <span class="filter-chip"
                        onclick="hostsPage._setFilter('vuln')">Vulnérables</span>
                </div>
            </div>

            <div id="hosts-table-container">
                ${HostTable.render(filtered)}
            </div>
        `;

        window.hostsPage = this;
    }

    _onSearch(value) {
        this.filter = value;
        const hosts = store.get('hosts') || [];
        const filtered = this._applyFilter(hosts);
        const tableContainer = document.getElementById('hosts-table-container');
        if (tableContainer) {
            tableContainer.innerHTML = HostTable.render(filtered);
        }
    }

    _setFilter(type) {
        if (type === 'vuln') {
            this.filter = '__vuln__';
        } else {
            this.filter = '';
        }
        this._render();
    }

    _applyFilter(hosts) {
        if (!this.filter) return hosts;
        if (this.filter === '__vuln__') {
            return hosts.filter(h => (h.vulnerabilities || []).length > 0);
        }
        const q = this.filter.toLowerCase();
        return hosts.filter(h =>
            (h.ip || '').toLowerCase().includes(q) ||
            (h.hostname || '').toLowerCase().includes(q) ||
            (h.vendor || '').toLowerCase().includes(q) ||
            (h.mac || '').toLowerCase().includes(q) ||
            (h.os_guess || '').toLowerCase().includes(q)
        );
    }
}

window.HostsPage = HostsPage;
