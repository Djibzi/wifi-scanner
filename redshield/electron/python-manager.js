// python-manager.js — Gère le process Python (Flask backend)
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

class PythonManager {
    constructor() {
        this.process = null;
        this.port = 5678;
        this.maxRetries = 30;
    }

    async start() {
        // Chercher le script Python ou l'exécutable compilé
        const serverPath = this._findServer();

        return new Promise((resolve, reject) => {
            // Lancer Python
            if (serverPath.endsWith('.py')) {
                this.process = spawn('python', [serverPath, '--port', String(this.port)], {
                    cwd: path.dirname(serverPath),
                    stdio: ['pipe', 'pipe', 'pipe'],
                });
            } else {
                // Exécutable compilé (PyInstaller)
                this.process = spawn(serverPath, ['--port', String(this.port)], {
                    cwd: path.dirname(serverPath),
                    stdio: ['pipe', 'pipe', 'pipe'],
                });
            }

            this.process.stdout.on('data', (data) => {
                console.log('[Python]', data.toString().trim());
            });

            this.process.stderr.on('data', (data) => {
                console.error('[Python]', data.toString().trim());
            });

            this.process.on('error', (err) => {
                reject(new Error(`Impossible de lancer Python : ${err.message}`));
            });

            this.process.on('exit', (code) => {
                if (code !== 0 && code !== null) {
                    console.error(`Python s'est arrêté avec le code ${code}`);
                }
                this.process = null;
            });

            // Attendre que le serveur soit prêt
            this._waitForReady()
                .then(() => resolve(this.port))
                .catch(reject);
        });
    }

    stop() {
        if (this.process) {
            this.process.kill();
            this.process = null;
        }
    }

    _findServer() {
        const isDev = process.argv.includes('--dev');

        if (isDev) {
            // Mode dev : script Python directement
            return path.join(__dirname, '..', 'backend', 'server.py');
        }

        // Mode production : exécutable dans les ressources
        const ext = process.platform === 'win32' ? '.exe' : '';
        const resourcePath = path.join(process.resourcesPath, 'backend', `server${ext}`);

        // Fallback sur le script Python si l'exécutable n'existe pas
        const fs = require('fs');
        if (fs.existsSync(resourcePath)) {
            return resourcePath;
        }
        return path.join(__dirname, '..', 'backend', 'server.py');
    }

    _waitForReady() {
        // Ping le healthcheck toutes les 500ms
        return new Promise((resolve, reject) => {
            let retries = 0;

            const check = () => {
                const req = http.get(`http://127.0.0.1:${this.port}/api/health`, (res) => {
                    if (res.statusCode === 200) {
                        resolve();
                    } else {
                        retry();
                    }
                });

                req.on('error', () => retry());
                req.setTimeout(1000, () => {
                    req.destroy();
                    retry();
                });
            };

            const retry = () => {
                retries++;
                if (retries >= this.maxRetries) {
                    reject(new Error('Le backend Python ne répond pas après 15 secondes'));
                } else {
                    setTimeout(check, 500);
                }
            };

            // Premier essai après 1 seconde
            setTimeout(check, 1000);
        });
    }
}

module.exports = PythonManager;
