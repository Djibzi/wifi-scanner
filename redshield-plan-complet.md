# REDSHIELD — Plan Complet
## Application Desktop Electron + Python · Thème Blood Red (Dark & Light)

---

## Identité visuelle

### Nom : REDSHIELD
### Icône : bouclier rouge

### Palette Dark Mode

```
Fond principal     : #0d0b0e (noir violacé)
Fond cartes        : #16121a (gris sombre chaud)
Fond tertiaire     : #1e1824 (hover, inputs)
Terminal           : #0a080c (quasi noir)

Texte principal    : #f0e8e8 (blanc chaud)
Texte secondaire   : #9a8a94 (gris rosé)
Texte discret      : #5a4a54 (gris foncé)

Accent principal   : #dc2626 (rouge vif)
Accent clair       : #f87171 (rouge clair)
Accent dim         : rgba(220,38,38,0.12)

Critique           : #ff3b5c (rouge rose)
Haute              : #fb923c (orange)
Moyenne            : #facc15 (jaune)
Faible             : #4ade80 (vert)
Info               : #a78bfa (violet)

Bordures           : rgba(220,38,38,0.1)
Bordures subtiles  : rgba(255,255,255,0.04)
```

### Palette Light Mode

```
Fond principal     : #faf5f5 (blanc rosé)
Fond cartes        : #ffffff (blanc pur)
Fond tertiaire     : #f5eeee (gris rosé clair)
Terminal           : #f0eaea (beige clair)

Texte principal    : #1a0a0e (noir chaud)
Texte secondaire   : #7a5a64 (brun rosé)
Texte discret      : #a08a94 (gris chaud)

Accent principal   : #c41c1c (rouge profond)
Accent clair       : #dc2626 (rouge vif)
Accent dim         : rgba(220,38,38,0.06)

Critique           : #c41c1c
Haute              : #c46a1c
Moyenne            : #a08a00
Faible             : #1c8a3c
Info               : #6a4aaa

Bordures           : rgba(220,38,38,0.12)
Bordures subtiles  : #ecdcdc
Ombres cartes      : 0 1px 3px rgba(100,40,40,0.06)
```

### Typographie

```
Titres / UI        : System UI (-apple-system, sans-serif)
Données / Code     : JetBrains Mono, Fira Code, monospace
Poids              : 400 (normal), 600 (semi-bold), 700/800 (titres)
```

### Principes de design

- Bordure rouge de 2px en haut des cartes métriques (indicateur de couleur)
- Bordure gauche colorée de 3px sur les alertes
- Pas de border-radius au-delà de 8px (cartes) ou 6px (boutons, badges)
- Toggle dark/light avec une pastille qui glisse
- Ombre portée sur les cartes en light mode uniquement
- Terminal avec fond plus sombre que le reste en dark, plus clair en light
- Badge de sévérité : monospace, uppercase, fond transparent coloré

---

## Architecture technique

### Stack

```
Frontend : Electron 28+ (fenêtre native)
           HTML / CSS / JavaScript vanilla (pas de framework)
           Chart.js (graphiques)
           D3.js (carte réseau)
           Socket.IO client (temps réel)

Backend  : Python 3.11+
           Flask + Flask-SocketIO (API + WebSocket)
           Scapy (paquets réseau)
           SQLite (stockage local)

Build    : PyInstaller (compiler Python en .exe)
           electron-builder (créer l'installeur)
```

### Structure des fichiers

```
redshield/
├── package.json
├── electron-builder.yml
│
├── electron/
│   ├── main.js                  # Fenêtre + lancement Python
│   ├── preload.js               # Bridge sécurisé
│   ├── python-manager.js        # Gère le process Python
│   ├── menu.js                  # Menu natif
│   └── tray.js                  # Icône barre système
│
├── frontend/
│   ├── index.html               # Shell SPA
│   ├── css/
│   │   ├── tokens-dark.css      # Variables dark mode
│   │   ├── tokens-light.css     # Variables light mode
│   │   ├── base.css             # Reset, typographie
│   │   ├── layout.css           # Sidebar, content, footer
│   │   ├── components.css       # Cartes, badges, barres, boutons
│   │   ├── dashboard.css
│   │   ├── scan.css
│   │   ├── network-map.css
│   │   ├── hosts.css
│   │   ├── vulns.css
│   │   ├── traffic.css
│   │   ├── report.css
│   │   ├── settings.css
│   │   └── animations.css
│   ├── js/
│   │   ├── app.js               # Init + listeners globaux
│   │   ├── router.js            # Navigation SPA
│   │   ├── api.js               # Client HTTP → Flask
│   │   ├── websocket.js         # Client WebSocket
│   │   ├── store.js             # État global réactif
│   │   ├── theme.js             # Toggle dark/light
│   │   ├── pages/
│   │   │   ├── dashboard.js
│   │   │   ├── scan.js
│   │   │   ├── network-map.js
│   │   │   ├── hosts.js
│   │   │   ├── host-detail.js
│   │   │   ├── vulnerabilities.js
│   │   │   ├── traffic.js
│   │   │   ├── report.js
│   │   │   └── settings.js
│   │   ├── components/
│   │   │   ├── metric-card.js
│   │   │   ├── severity-badge.js
│   │   │   ├── progress-bar.js
│   │   │   ├── terminal.js
│   │   │   ├── score-gauge.js
│   │   │   ├── alert-row.js
│   │   │   ├── host-table.js
│   │   │   ├── vuln-card.js
│   │   │   ├── toast.js
│   │   │   ├── theme-toggle.js
│   │   │   └── charts.js
│   │   └── lib/
│   │       ├── chart.min.js
│   │       ├── d3.min.js
│   │       └── socket.io.min.js
│   └── assets/
│       ├── icons/               # SVG par type d'appareil
│       ├── app-icon.png
│       ├── app-icon.ico
│       └── app-icon.icns
│
├── backend/
│   ├── server.py                # Flask + SocketIO
│   ├── api/
│   │   ├── routes_scan.py
│   │   ├── routes_hosts.py
│   │   ├── routes_vulns.py
│   │   ├── routes_traffic.py
│   │   ├── routes_report.py
│   │   ├── routes_settings.py
│   │   └── routes_wifi.py
│   ├── core/
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── logger.py
│   │   ├── models.py
│   │   └── events.py
│   ├── modules/
│   │   ├── wifi_analyzer.py
│   │   ├── host_discovery.py
│   │   ├── port_scanner.py
│   │   ├── service_detector.py
│   │   ├── os_fingerprinter.py
│   │   ├── vuln_detector.py
│   │   ├── dns_analyzer.py
│   │   ├── credential_tester.py
│   │   └── traffic_analyzer.py
│   ├── vuln_db/
│   │   ├── default_credentials.json
│   │   ├── known_vulns.json
│   │   └── dangerous_ports.json
│   └── requirements.txt
│
└── scripts/
    ├── build-win.bat
    ├── build-mac.sh
    └── build-linux.sh
```

---

## Système de thème Dark/Light

### tokens-dark.css

```css
[data-theme="dark"] {
  --bg:           #0d0b0e;
  --bg2:          #16121a;
  --bg3:          #1e1824;
  --bg-hover:     #241d2e;
  --bg-term:      #0a080c;

  --text:         #f0e8e8;
  --text2:        #9a8a94;
  --text3:        #5a4a54;

  --accent:       #dc2626;
  --accent-light: #f87171;
  --accent-dim:   rgba(220,38,38,0.12);

  --crit:         #ff3b5c;
  --high:         #fb923c;
  --med:          #facc15;
  --low:          #4ade80;
  --info:         #a78bfa;

  --border:       rgba(220,38,38,0.1);
  --border-sub:   rgba(255,255,255,0.04);
  --shadow:       none;
}
```

### tokens-light.css

```css
[data-theme="light"] {
  --bg:           #faf5f5;
  --bg2:          #ffffff;
  --bg3:          #f5eeee;
  --bg-hover:     #f0e8e8;
  --bg-term:      #f0eaea;

  --text:         #1a0a0e;
  --text2:        #7a5a64;
  --text3:        #a08a94;

  --accent:       #c41c1c;
  --accent-light: #dc2626;
  --accent-dim:   rgba(220,38,38,0.06);

  --crit:         #c41c1c;
  --high:         #c46a1c;
  --med:          #a08a00;
  --low:          #1c8a3c;
  --info:         #6a4aaa;

  --border:       rgba(220,38,38,0.12);
  --border-sub:   #ecdcdc;
  --shadow:       0 1px 3px rgba(100,40,40,0.06);
}
```

### theme.js — Toggle

```javascript
class ThemeManager {
    constructor() {
        this.current = localStorage.getItem('theme') || 'dark';
        this.apply();
    }

    toggle() {
        this.current = this.current === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', this.current);
        this.apply();
    }

    apply() {
        document.documentElement.setAttribute('data-theme', this.current);
    }
}
```

---

## Pages de l'application

### Page 1 — Dashboard
- Bandeau info WiFi (SSID, sécurité, signal, nombre d'appareils)
- 4 cartes métriques (Score, Critiques, Hautes, Appareils)
- Liste des menaces actives avec badges de sévérité
- Graphiques : barres de vulnérabilités + liste des types d'appareils
- Bouton "Lancer un scan" centré en bas

### Page 2 — Scanner
- Titre + info cible
- Barre de progression avec dégradé rouge→violet
- Grille des modules (statut en temps réel via WebSocket)
- Split view : découvertes live à gauche, terminal à droite
- Bouton stop scan

### Page 3 — Carte réseau
- Vue graphique D3.js avec appareils positionnés
- Lignes en pointillés entre routeur et appareils
- Nœuds colorés par risque avec badges de compteur de vulns
- Panneau de détail au clic sur un appareil
- Légende des couleurs

### Page 4 — Appareils
- Tableau triable et filtrable
- Colonnes : Risque, Appareil, IP, OS, Ports ouverts
- Barre de recherche
- Filtres par type et sévérité
- Clic sur une ligne ouvre le détail

### Page 5 — Détail appareil
- Infos complètes (IP, MAC, fabricant, OS, type)
- Liste des ports ouverts avec service et version
- Liste des vulnérabilités de cet appareil
- Boutons : Re-scanner, Copier, Exporter

### Page 6 — Vulnérabilités
- Onglets de filtrage par sévérité avec compteurs
- Cartes dépliables pour chaque vulnérabilité
- Appareil concerné, description, impact, remédiation
- Référence CVE si applicable

### Page 7 — Trafic
- Graphique temps réel (paquets/sec)
- Répartition des protocoles
- Tableau des flux réseau
- Alertes temps réel (ARP spoofing, trafic HTTP en clair)

### Page 8 — Rapport
- Jauge circulaire du score animée
- Résumé exécutif
- Actions prioritaires numérotées
- Export PDF / Markdown / JSON

### Page 9 — Paramètres
- Config scan (timeout, threads, ports)
- Config credentials (wordlist, max tentatives)
- Interface (thème dark/light, langue, notifications)
- Réseau (interface, mode promiscuous)
- Base de données (MAJ CVE, historique)

---

## API REST (backend Python)

```
GET    /api/health                    Healthcheck
GET    /api/wifi                      Infos WiFi

POST   /api/scan/start               Lancer un scan
POST   /api/scan/stop                Arrêter le scan
GET    /api/scan/status              Statut du scan

GET    /api/hosts                     Liste des appareils
GET    /api/hosts/:ip                 Détail d'un appareil

GET    /api/vulnerabilities           Liste des vulnérabilités

POST   /api/traffic/start             Démarrer la capture
POST   /api/traffic/stop              Arrêter la capture
GET    /api/traffic/stats             Stats trafic

GET    /api/report                    Données du rapport
GET    /api/report/export/:format     Exporter (pdf/md/json)

GET    /api/history                   Historique des scans

GET    /api/settings                  Configuration
PUT    /api/settings                  Modifier la config
```

## Événements WebSocket (temps réel)

```
scan:started          Scan démarré
scan:progress         Progression (module, %, temps)
scan:module_complete  Module terminé
scan:finished         Scan terminé (score)

host:found            Appareil découvert
port:found            Port ouvert trouvé
vuln:found            Vulnérabilité détectée

traffic:stats         Stats trafic (toutes les 2s)
traffic:alert         Alerte trafic

log:entry             Ligne de log pour le terminal
```

---

## Modules Python de scan

### 1. wifi_analyzer.py
Analyse du réseau WiFi : SSID, sécurité, canal, WPS, PMF, DNS
Vulnérabilités : réseau ouvert, WEP, WPA+TKIP, WPS activé, DNS suspect

### 2. host_discovery.py
Découverte des appareils : scan ARP, ping sweep, mDNS, NetBIOS
Enrichissement : OUI lookup (MAC → fabricant), DNS inverse, hostname

### 3. port_scanner.py
Scan TCP Connect multi-threadé (concurrent.futures)
Top 100 / Top 1000 / Full 65535 selon le mode
Timeouts adaptés au réseau local

### 4. service_detector.py
Banner grabbing sur chaque port ouvert
Identification HTTP (headers, titre, techno)
Détection des panneaux d'administration
Analyse des certificats TLS

### 5. os_fingerprinter.py
Heuristique TTL + ports ouverts + MAC vendor + bannières
Combinaison des indices pour estimation fiable

### 6. vuln_detector.py
Services dangereux (Telnet, FTP, VNC, Redis, MongoDB, RDP, MQTT, SNMP)
Identifiants par défaut (avec consentement utilisateur)
Vulnérabilités par version de service (base CVE locale)
Analyse du routeur (UPnP, admin HTTP, firmware)
Segmentation réseau

### 7. dns_analyzer.py
Vérification des serveurs DNS configurés
Détection de DNS suspects

### 8. credential_tester.py
Test des identifiants par défaut sur SSH, FTP, HTTP, VNC, MySQL, SNMP, MQTT
Multi-protocole avec base de credentials par appareil

### 9. traffic_analyzer.py
Sniffing passif avec Scapy
Détection protocoles non chiffrés, anomalies ARP, broadcast storms
Stats en temps réel via WebSocket

---

## Rapport de sécurité

### Score (0-100)

```
Score initial : 100

Déductions :
  Vulnérabilité CRITIQUE  : -20 pts
  Vulnérabilité HAUTE     : -10 pts
  Vulnérabilité MOYENNE   :  -5 pts
  Vulnérabilité FAIBLE    :  -2 pts

Bonus :
  WPA3                    :  +5 pts
  WPS désactivé           :  +3 pts
  Aucun Telnet/FTP        :  +5 pts
  DNS de confiance         :  +2 pts
  Aucun cred par défaut   :  +5 pts

Grades :
  90-100 : A (Excellent)
  75-89  : B (Bon)
  60-74  : C (Acceptable)
  40-59  : D (Insuffisant)
  0-39   : F (Critique)
```

### Contenu du rapport
1. Résumé exécutif (score, top 3 risques)
2. Infos réseau WiFi + vulnérabilités WiFi
3. Inventaire des appareils (tableau)
4. Détail de chaque vulnérabilité (description, preuve, remédiation)
5. Recommandations globales
6. Export : HTML, PDF, Markdown, JSON

---

## Build et distribution

### Compiler le backend Python

```bash
cd backend/
pip install pyinstaller
pyinstaller --onefile --name server server.py \
  --hidden-import=eventlet \
  --hidden-import=flask_socketio \
  --add-data "vuln_db:vuln_db"
```

### Configurer electron-builder

```yaml
appId: com.redshield.app
productName: REDSHIELD

extraResources:
  - from: "backend/dist/server${ext}"
    to: "backend/server${ext}"
  - from: "backend/vuln_db/"
    to: "backend/vuln_db/"

win:
  target: nsis
  icon: frontend/assets/app-icon.ico
  requestedExecutionLevel: requireAdministrator

mac:
  target: dmg
  icon: frontend/assets/app-icon.icns

linux:
  target: [AppImage, deb]
  icon: frontend/assets/app-icon.png
```

### Commandes de build

```bash
npm run build:python          # Compile Python en .exe
npm run build:win             # Crée l'installeur Windows
npm run build:mac             # Crée le .dmg macOS
npm run build:linux           # Crée AppImage + .deb
```

---

## Dépendances

### Python (requirements.txt)

```
flask==3.0.0
flask-socketio==5.3.6
flask-cors==4.0.0
eventlet==0.35.1
scapy==2.5.0
impacket==0.11.0
paramiko==3.4.0
requests==2.31.0
netifaces==0.11.0
mac-vendor-lookup==0.1.12
cryptography==41.0.7
pyOpenSSL==23.3.0
pypykatz==0.6.8
zeroconf==0.131.0
paho-mqtt==1.6.1
rich==13.7.0
jinja2==3.1.2
fpdf2==2.7.6
```

### Node.js (package.json)

```json
{
  "devDependencies": {
    "electron": "^28.0.0",
    "electron-builder": "^24.9.0"
  }
}
```

---

## Planning de développement

### Phase 1 — Fondations (Semaine 1)
- Setup Electron + Flask minimal
- python-manager.js (lancement auto de Python)
- Healthcheck + écran de chargement
- Shell HTML avec sidebar et routeur SPA
- Système de thème dark/light avec CSS variables
- Vérifier : Electron lance Python, affiche l'interface

### Phase 2 — Communication (Semaine 2)
- api.js (client HTTP)
- websocket.js (client WebSocket)
- store.js (état global)
- events.py (émission WebSocket côté Python)
- Test aller-retour : clic → Python → événement → affichage

### Phase 3 — Dashboard (Semaine 3)
- Composants : metric-card, severity-badge, alert-row, charts
- Page dashboard avec données réelles
- Graphiques Chart.js
- Connexion aux routes API Python

### Phase 4 — Scanner (Semaine 4)
- Page de configuration du scan
- Barre de progression temps réel
- Terminal de logs
- Grille des modules avec statut live
- Intégrer wifi_analyzer.py et host_discovery.py

### Phase 5 — Modules de scan (Semaine 5-6)
- port_scanner.py
- service_detector.py
- os_fingerprinter.py
- vuln_detector.py
- credential_tester.py
- dns_analyzer.py
- Chaque module émet des événements WebSocket en temps réel

### Phase 6 — Carte réseau (Semaine 7)
- Graphe D3.js force-directed
- Nœuds interactifs (drag, clic, zoom)
- Code couleur par risque
- Panneau de détail au clic

### Phase 7 — Pages secondaires (Semaine 8)
- Liste des appareils (tableau triable/filtrable)
- Détail d'un appareil
- Liste des vulnérabilités (onglets par sévérité)
- Page trafic temps réel

### Phase 8 — Rapport (Semaine 9)
- Jauge de score animée
- Résumé exécutif
- Actions prioritaires
- Export PDF / Markdown / JSON
- Page paramètres

### Phase 9 — Fonctionnalités natives (Semaine 10)
- Menu natif (Fichier, Affichage, Aide)
- System tray
- Notifications système
- Raccourcis clavier
- Dialogues natifs (Enregistrer sous)

### Phase 10 — Build et distribution (Semaine 11)
- Compiler Python avec PyInstaller
- Configurer electron-builder
- Tester sur Windows, macOS, Linux
- Créer l'installeur final
- Icône, splash screen, about dialog

### Phase 11 — Polish (Semaine 12)
- Animations de transition entre pages
- Gestion d'erreurs (Python crash, réseau indisponible)
- États vides (pas de scan, pas de données)
- Performance (lazy loading, pagination)
- Tests finaux
