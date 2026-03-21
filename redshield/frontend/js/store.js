// store.js — État global réactif de l'application

class Store {
    constructor() {
        this._state = {
            backendPort: null,
            backendOnline: false,
            scanning: false,
            scanProgress: 0,
            scanModule: '',
            wifi: null,
            hosts: [],
            vulnerabilities: [],
            score: 0,
            grade: '',
            settings: {},
            trafficRunning: false,
            trafficStats: null,
        };
        this._listeners = {};
    }

    get(key) {
        return this._state[key];
    }

    set(key, value) {
        const old = this._state[key];
        this._state[key] = value;
        if (old !== value) {
            this._notify(key, value, old);
        }
    }

    // Écouter les changements d'un champ
    on(key, callback) {
        if (!this._listeners[key]) {
            this._listeners[key] = [];
        }
        this._listeners[key].push(callback);
    }

    off(key, callback) {
        if (this._listeners[key]) {
            this._listeners[key] = this._listeners[key].filter(cb => cb !== callback);
        }
    }

    _notify(key, value, old) {
        const cbs = this._listeners[key] || [];
        cbs.forEach(cb => {
            try { cb(value, old); } catch (e) { console.error('Store listener error:', e); }
        });
    }

    // Raccourcis
    getState() {
        return { ...this._state };
    }
}

window.store = new Store();
