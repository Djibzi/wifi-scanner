# REDSHIELD

Scanner de securite reseau WiFi avec interface graphique native Windows.

![Version](https://img.shields.io/badge/Version-1.1.0-red)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## Presentation

REDSHIELD est un outil d'audit de securite reseau qui analyse votre WiFi, detecte les appareils connectes, scanne les ports ouverts, identifie les vulnerabilites potentielles et permet de bypasser les portails captifs. Il se presente sous forme d'une application desktop avec une interface moderne.

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
- **🔓 Portal (v1.1)** — Module de bypass des portails captifs (detection, chasse aux clients, MAC spoofing, audit)
- **Theme dark/light** — Interface adaptable selon vos preferences

---

## Nouveaute v1.1 — Captive Portal Bypass

La version 1.1 ajoute un module complet de contournement des portails captifs.

### Detection

Identifie automatiquement la presence d'un portail captif sur le reseau :
- Type de logiciel (Nodogsplash, CoovaChilli, UniFi, pfSense, Cisco, Aruba, Meraki...)
- Methode d'authentification (MAC uniquement, login/password, 802.1X)
- Presence d'un proxy (Squid, etc.)
- Statut du portail (en ligne, hors ligne, partiel)
- Hijacking DNS

### Clients

Ecoute le trafic reseau pour identifier les appareils autorises par le portail :
- Separation claire entre appareils autorises (trafic Internet) et bloques
- Score de confiance base sur le nombre de paquets, la diversite des destinations et la duree d'observation
- Destinations resolues (google.com, etc.)
- Action directe "Utiliser cette MAC" vers le Spoofer

### Spoofer

Change l'adresse MAC de la carte reseau Windows pour bypasser le portail :
- Ecriture dans le registre Windows (`NetworkAddress`)
- Redemarrage automatique de l'adaptateur via netsh
- Renouvellement DHCP optionnel
- Test d'acces Internet automatique
- Log temps reel de chaque etape via WebSocket
- Restauration automatique de la MAC originale a la fermeture

### Audit de securite

Rapport complet avec score 0-100 et grade A-F :
- Detection MAC-only auth (CRITIQUE — CVSS 9.1)
- Isolation des clients (CRITIQUE — CVSS 8.5)
- HTTPS sur le portail (HAUTE — CVSS 7.4)
- Timeout de session (HAUTE — CVSS 6.8)
- Fuite d'info proxy (MOYENNE — CVSS 5.3)
- Disponibilite 802.1X (MOYENNE)

---

## Installation rapide

### Option 1 : Executable (recommande)

1. Telechargez **REDSHIELD.exe** depuis la page [Releases](https://github.com/Djibzi/wifi-scanner/releases/latest)
2. Lancez-le **en tant qu'administrateur** (necessaire pour le scan reseau et le MAC spoofing)
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

---

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
│   │   ├── server.py       # Serveur principal (v1.1.0)
│   │   ├── api/            # Routes API (scan, hosts, vulns, traffic, radar, portal...)
│   │   ├── core/           # Events temps reel, base de donnees SQLite
│   │   ├── modules/        # Proxy vers les modules racine + modules portal
│   │   │   ├── portal_detector.py      # Detection portail captif
│   │   │   ├── portal_client_hunter.py # Identification clients autorises
│   │   │   ├── portal_mac_spoofer.py   # MAC spoofing Windows
│   │   │   └── portal_auditor.py       # Audit de securite portail
│   │   └── vuln_db/        # Signatures portails captifs
│   └── frontend/           # Interface utilisateur
│       ├── index.html      # Page principale
│       ├── css/            # Styles (dark/light theme, composants, portal)
│       └── js/             # Application JS (router, pages, composants)
│           ├── pages/portal.js             # Page Portal (4 onglets)
│           └── components/portal-*.js      # Composants Detection/Clients/Spoofer/Audit
└── logs/                   # Logs de scan (generes automatiquement)
```

---

## Dependances principales

| Package | Usage |
|---------|-------|
| Flask | Serveur backend API |
| Flask-SocketIO | Communication temps reel (WebSocket) |
| pywebview | Fenetre native Windows |
| scapy | Analyse de paquets reseau + ecoute trafic portal |
| requests | Detection portail captif (HTTP) |
| Jinja2 | Templates de rapports |
| PyInstaller | Build de l'executable |

## Pre-requis

- **Windows 10/11**
- **Python 3.10+** (si execution depuis les sources)
- **Npcap** (installe automatiquement avec Wireshark, necessaire pour scapy)
- **Droits administrateur** pour le scan reseau et le MAC spoofing

---

## Utilisation

1. **Lancez un scan** — Choisissez le mode (rapide, complet, exhaustif) et lancez
2. **Dashboard** — Vue d'ensemble avec score de securite, alertes et bandeau portail captif si detecte
3. **Appareils** — Liste de tous les appareils detectes avec details (ports, OS, services)
4. **Vulnerabilites** — Liste des failles detectees classees par severite
5. **Radar** — Visualisation temps reel des appareils avec ping
6. **Trafic** — Analyse passive du trafic reseau
7. **🔓 Portal** — Bypass de portail captif (detection → clients → spoof → audit)
8. **Rapports** — Generation de rapports exportables

---

## Changelog

### v1.1.0
- Nouveau module Portal — Captive Portal Bypass complet
- Detection automatique du type de portail (10 signatures)
- Identification des clients autorises par ecoute du trafic
- MAC spoofing Windows via registre + redemarrage adaptateur
- Audit de securite avec score 0-100 et grade A-F
- Bandeau d'alerte portail sur le Dashboard
- Section Portal dans les Parametres
- Mise a jour de la base de vulnerabilites (5 nouvelles entrees portail)

### v1.0.0
- Version initiale
- Scanner reseau, radar, trafic, vulnerabilites, rapports

---

## Avertissement legal

Cet outil est concu pour auditer **votre propre reseau**. L'utilisation sur des reseaux sans autorisation est illegale. L'auteur decline toute responsabilite en cas d'utilisation malveillante.

## Licence

MIT
