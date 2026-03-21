# REDSHIELD

Scanner de securite reseau WiFi avec interface graphique native Windows.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## Presentation

REDSHIELD est un outil d'audit de securite reseau qui analyse votre WiFi, detecte les appareils connectes, scanne les ports ouverts et identifie les vulnerabilites potentielles. Il se presente sous forme d'une application desktop avec une interface moderne.

### Fonctionnalites principales

- **Decouverte reseau** — Detection automatique de tous les appareils (PC, telephones, IoT, imprimantes, routeurs) avec identification par nom d'hote et type
- **Scan de ports** — Mode rapide (ports critiques), complet (top 1000) ou exhaustif (65535 ports)
- **Detection de vulnerabilites** — Base de donnees integree de CVE et configurations risquees
- **Radar en temps reel** — Visualisation animee des appareils avec ping, latence et etat de connexion
- **Analyse de trafic** — Capture passive des paquets reseau avec details par appareil
- **Test d'identifiants** — Verification des mots de passe par defaut sur les services detectes
- **Analyse WiFi** — Evaluation du chiffrement, force du signal, configuration du routeur
- **Analyse DNS** — Detection de serveurs DNS suspects ou non securises
- **Rapports** — Generation HTML, Markdown et JSON avec score de securite global
- **Theme dark/light** — Interface adaptable selon vos preferences

## Installation rapide

### Option 1 : Executable (recommande)

1. Telechargez **REDSHIELD.exe** depuis la page [Releases](https://github.com/Djibzi/wifi-scanner/releases/latest)
2. Lancez-le **en tant qu'administrateur** (necessaire pour le scan reseau)
3. L'application s'ouvre automatiquement

> Windows Defender peut afficher un avertissement car l'exe n'est pas signe numeriquement. Cliquez sur "Informations complementaires" puis "Executer quand meme".

### Option 2 : Depuis les sources

```bash
# Cloner le repo
git clone https://github.com/Djibzi/wifi-scanner.git
cd wifi-scanner

# Installer les dependances
pip install -r redshield/backend/requirements.txt

# Lancer l'application
python redshield/redshield.py
```

### Option 3 : Construire l'exe vous-meme

```bash
cd redshield
python build.py
# L'exe sera dans redshield/dist/REDSHIELD.exe
```

## Architecture

```
wifi-scanner/
├── core/                   # Configuration, logger, modeles de donnees
│   ├── config.py           # Ports critiques, modes de scan, timeouts
│   ├── logger.py           # Systeme de logging avec fichiers rotatifs
│   └── models.py           # Classes Host, Port, Vulnerability, ScanResult
├── modules/                # Moteurs de scan
│   ├── host_discovery.py   # Decouverte ARP + resolution de noms
│   ├── port_scanner.py     # Scan TCP multi-thread
│   ├── service_detector.py # Identification de services (banners)
│   ├── vuln_detector.py    # Detection de vulnerabilites
│   ├── wifi_analyzer.py    # Analyse WiFi (chiffrement, signal)
│   ├── dns_analyzer.py     # Analyse DNS
│   ├── credential_tester.py# Test d'identifiants par defaut
│   └── traffic_analyzer.py # Capture et analyse de trafic
├── vuln_db/                # Bases de donnees JSON de vulnerabilites
├── reports/                # Generateur de rapports + templates Jinja2
├── redshield/              # Application desktop
│   ├── redshield.py        # Point d'entree (pywebview + Flask)
│   ├── build.py            # Script de build PyInstaller
│   ├── backend/            # Serveur Flask + API REST + WebSocket
│   │   ├── server.py       # Serveur principal
│   │   ├── api/            # Routes API (scan, hosts, vulns, traffic, radar...)
│   │   ├── core/           # Events temps reel, base de donnees SQLite
│   │   └── modules/        # Proxy vers les modules racine
│   └── frontend/           # Interface utilisateur
│       ├── index.html      # Page principale
│       ├── css/            # Styles (dark/light theme, composants)
│       └── js/             # Application JS (router, pages, composants)
└── logs/                   # Logs de scan (generes automatiquement)
```

## Dependances principales

| Package | Usage |
|---------|-------|
| Flask | Serveur backend API |
| Flask-SocketIO | Communication temps reel (WebSocket) |
| pywebview | Fenetre native Windows |
| scapy | Analyse de paquets reseau |
| Jinja2 | Templates de rapports |
| PyInstaller | Build de l'executable |

## Pre-requis

- **Windows 10/11**
- **Python 3.10+** (si execution depuis les sources)
- **Npcap** (installe automatiquement avec Wireshark, necessaire pour scapy)
- **Droits administrateur** pour le scan reseau

## Utilisation

1. **Lancez un scan** — Choisissez le mode (rapide, complet, exhaustif) et lancez
2. **Dashboard** — Vue d'ensemble avec score de securite et statistiques
3. **Appareils** — Liste de tous les appareils detectes avec details (ports, OS, services)
4. **Vulnerabilites** — Liste des failles detectees classees par severite
5. **Radar** — Visualisation temps reel des appareils avec ping
6. **Trafic** — Analyse passive du trafic reseau
7. **Rapports** — Generation de rapports exportables

## Avertissement legal

Cet outil est concu pour auditer **votre propre reseau**. L'utilisation sur des reseaux sans autorisation est illegale. L'auteur decline toute responsabilite en cas d'utilisation malveillante.

## Licence

MIT
