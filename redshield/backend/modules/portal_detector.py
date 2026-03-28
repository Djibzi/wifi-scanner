# portal_detector.py — Détection de portail captif
# Analyse le réseau pour détecter si un portail captif est actif

import os
import re
import socket
import subprocess
import threading
import time

import requests

# Signatures de portails connus chargées depuis le fichier JSON
_signatures = None


def _load_signatures():
    global _signatures
    if _signatures is not None:
        return _signatures
    try:
        import json
        sig_path = os.path.join(os.path.dirname(__file__), '..', 'vuln_db', 'captive_portal_signatures.json')
        with open(sig_path, 'r', encoding='utf-8') as f:
            _signatures = json.load(f)
    except Exception:
        _signatures = {}
    return _signatures


# URL de test de connectivité (n'affiche jamais de redirection sur réseau normal)
CONNECTIVITY_CHECKS = [
    'http://connectivitycheck.gstatic.com/generate_204',
    'http://captive.apple.com/hotspot-detect.html',
    'http://www.msftconnecttest.com/connecttest.txt',
]


class PortalDetector:
    """
    Détecte la présence d'un portail captif sur le réseau actuel.

    Méthode :
    1. Tenter une requête HTTP vers un site de connectivité connu
    2. Si redirection → portail captif présent
    3. Analyser les headers pour identifier le logiciel du portail
    4. Scanner les ports du portail (80, 443, 2050, 8080, 8443)
    5. Identifier le proxy (Squid, etc.)
    6. Vérifier le DNS
    7. Déterminer la méthode d'authentification
    """

    def __init__(self):
        self._result = None
        self._running = False

    def detect(self):
        """Lance la détection complète. Retourne un dict avec les résultats."""
        self._running = True
        result = {
            'detected': False,
            'type': None,
            'portal_ip': None,
            'portal_port': None,
            'redirect_url': None,
            'proxy': None,
            'auth_method': 'unknown',
            'portal_status': 'unknown',
            'dns_hijack': False,
            'https_available': False,
            'error': None,
        }

        try:
            # Étape 1 : Vérifier la connectivité + détecter la redirection
            redirect_url, portal_ip = self._check_connectivity()
            if redirect_url:
                result['detected'] = True
                result['redirect_url'] = redirect_url
                result['portal_ip'] = portal_ip or self._extract_ip(redirect_url)
                result['portal_port'] = self._extract_port(redirect_url)

                # Étape 2 : Identifier le type de portail
                portal_type = self._identify_portal_type(redirect_url, result['portal_ip'])
                result['type'] = portal_type

                # Étape 3 : Tester le statut du portail (up/down/partial)
                portal_status = self._check_portal_status(redirect_url)
                result['portal_status'] = portal_status

                # Étape 4 : Détecter un proxy
                proxy = self._detect_proxy(result['portal_ip'])
                result['proxy'] = proxy

                # Étape 5 : Méthode d'authentification
                auth_method = self._detect_auth_method(result['portal_ip'], result['portal_port'])
                result['auth_method'] = auth_method

                # Étape 6 : DNS hijacking
                result['dns_hijack'] = self._check_dns_hijack()

                # Étape 7 : HTTPS disponible
                if result['portal_ip'] and result['portal_port']:
                    result['https_available'] = self._check_https(result['portal_ip'])
            else:
                result['detected'] = False
                result['portal_status'] = 'none'

        except Exception as e:
            result['error'] = str(e)

        self._result = result
        self._running = False
        return result

    def _check_connectivity(self):
        """Teste la connectivité HTTP et détecte une redirection de portail captif."""
        for url in CONNECTIVITY_CHECKS:
            try:
                resp = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CaptiveNetworkSupport'},
                )
                # Code 204 ou 200 avec contenu attendu = pas de portail
                if resp.status_code == 204:
                    return None, None
                if resp.status_code == 200 and 'generate_204' in url:
                    # Devrait retourner 204, mais retourne 200 → portail
                    pass

                # Redirection → portail captif
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    portal_ip = self._extract_ip(location)
                    return location, portal_ip

                # 200 avec contenu inattendu → portail qui intercepte
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(kw in content for kw in ['login', 'captive', 'portal', 'hotspot', 'accept']):
                        portal_ip = self._extract_ip(resp.url)
                        return resp.url, portal_ip

            except requests.exceptions.ConnectionError:
                # Pas de connexion du tout → portail possible
                return self._get_gateway_url(), self._get_gateway_ip()
            except Exception:
                continue

        return None, None

    def _get_gateway_ip(self):
        """Récupère l'IP de la passerelle par défaut."""
        try:
            import subprocess
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if 'Passerelle' in line or 'Gateway' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            return ip
        except Exception:
            pass
        return None

    def _get_gateway_url(self):
        """Construit l'URL de la passerelle."""
        gw = self._get_gateway_ip()
        if gw:
            return f'http://{gw}/'
        return None

    def _extract_ip(self, url):
        """Extrait l'IP ou le hostname d'une URL."""
        if not url:
            return None
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            if host and re.match(r'\d+\.\d+\.\d+\.\d+', host):
                return host
            # Résoudre le hostname
            if host:
                return socket.gethostbyname(host)
        except Exception:
            pass
        return None

    def _extract_port(self, url):
        """Extrait le port d'une URL."""
        if not url:
            return 80
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == 'https' else 80
        except Exception:
            return 80

    def _identify_portal_type(self, redirect_url, portal_ip):
        """Identifie le type de portail captif depuis les signatures connues."""
        sigs = _load_signatures()
        if not sigs:
            return 'unknown'

        # Tenter de récupérer la page du portail
        try:
            resp = requests.get(redirect_url, timeout=5, verify=False)
            html = resp.text
            headers_str = str(resp.headers).lower()
        except Exception:
            html = ''
            headers_str = ''

        # Vérifier chaque signature
        for portal_name, sig_data in sigs.items():
            matched = False
            for check in sig_data.get('checks', []):
                check_type = check.get('type', 'html')
                value = check.get('value', '').lower()

                if check_type == 'html' and value in html.lower():
                    matched = True
                    break
                elif check_type == 'header' and value in headers_str:
                    matched = True
                    break
                elif check_type == 'url' and value in redirect_url.lower():
                    matched = True
                    break

            if matched:
                return portal_name

        # Détection par port si l'IP est connue
        if portal_ip:
            common_ports = {2050: 'nodogsplash', 3990: 'coovachilli', 8080: 'generic'}
            for port, name in common_ports.items():
                if self._is_port_open(portal_ip, port):
                    return name

        return 'unknown'

    def _check_portal_status(self, redirect_url):
        """Vérifie si la page de login du portail répond."""
        try:
            resp = requests.get(redirect_url, timeout=5, verify=False)
            if resp.status_code == 200:
                return 'up'
            elif resp.status_code in (502, 503, 504):
                return 'down'
            else:
                return 'partial'
        except Exception:
            return 'down'

    def _detect_proxy(self, portal_ip):
        """Détecte si un proxy est actif sur le réseau."""
        if not portal_ip:
            return None

        proxy_ports = {
            8080: 'squid',
            3128: 'squid',
            8888: 'generic',
            8118: 'privoxy',
        }

        for port, proxy_type in proxy_ports.items():
            if self._is_port_open(portal_ip, port):
                # Tenter d'identifier la version du proxy
                version = self._get_proxy_version(portal_ip, port, proxy_type)
                return {
                    'type': proxy_type,
                    'port': port,
                    'version': version,
                }

        return None

    def _get_proxy_version(self, ip, port, proxy_type):
        """Essaie de récupérer la version du proxy via une requête d'erreur."""
        try:
            resp = requests.get(
                f'http://{ip}:{port}/nonexistent_path_xyz',
                timeout=3,
                verify=False,
                proxies={'http': f'http://{ip}:{port}'},
            )
            # Chercher "squid" ou la version dans la réponse
            content = resp.text.lower()
            match = re.search(r'squid/(\d+\.\d+)', content)
            if match:
                return f'Squid/{match.group(1)}'
        except Exception:
            pass
        return None

    def _detect_auth_method(self, portal_ip, portal_port):
        """Détermine la méthode d'authentification du portail."""
        if not portal_ip:
            return 'unknown'

        # Vérifier 802.1X (EAP) — présence dans les beacons, pas détectable facilement
        # Pour l'instant, heuristique basée sur le type de portail

        try:
            url = f'http://{portal_ip}:{portal_port or 80}/'
            resp = requests.get(url, timeout=5, verify=False)
            html = resp.text.lower()

            # Formulaire login/password → authentification par credentials
            if 'password' in html or 'mot de passe' in html:
                return 'credentials'

            # Seulement des boutons "Accept" → MAC uniquement
            if ('accept' in html or 'connexion' in html) and 'password' not in html:
                return 'mac_only'

            # Présence de champs email/phone → authentification sociale
            if 'email' in html or 'phone' in html:
                return 'social'

        except Exception:
            pass

        return 'mac_only'  # Défaut conservateur pour les portails qui ne répondent pas

    def _check_dns_hijack(self):
        """Vérifie si le DNS est détourné par le portail."""
        try:
            # Résoudre un domaine inexistant — devrait retourner NXDOMAIN
            # Si le portail hijacke le DNS, il retournera une IP
            fake_domain = 'this-domain-should-not-exist-xyz123abc.com'
            try:
                ip = socket.gethostbyname(fake_domain)
                # Si une IP est retournée, le DNS est probablement hijacké
                return True
            except socket.gaierror:
                # NXDOMAIN = DNS normal
                return False
        except Exception:
            return False

    def _check_https(self, portal_ip):
        """Vérifie si le portail est accessible en HTTPS."""
        try:
            resp = requests.get(
                f'https://{portal_ip}/',
                timeout=3,
                verify=False,
            )
            return resp.status_code < 500
        except Exception:
            return False

    def _is_port_open(self, ip, port, timeout=1):
        """Vérifie si un port est ouvert."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
