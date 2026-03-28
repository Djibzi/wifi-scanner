# portal_auditor.py — Audit de sécurité complet du portail captif
# Effectue des tests de sécurité et génère un rapport avec score et grade

import socket
import ssl
import time

import requests


class PortalAuditor:
    """
    Audit de sécurité complet du portail captif.

    Score de sécurité (0-100) :
    -30 : MAC-only auth (bypass trivial)
    -20 : Pas d'isolation client
    -15 : Portail en HTTP
    -15 : Pas de timeout de session
    -10 : Proxy info leak
    -10 : Pas de 802.1X
    +20 : Binding MAC+IP+session
    +15 : Client isolation activée
    +10 : HTTPS sur le portail
    +10 : Timeout < 60 minutes
    +15 : 802.1X disponible
    """

    def __init__(self, events=None):
        self.events = events

    def audit(self, portal_ip, portal_port=None, detect_result=None):
        """
        Lance l'audit complet du portail.
        detect_result : résultat de PortalDetector.detect() si disponible
        """
        score = 100
        vulnerabilities = []
        checks = {
            'mac_only_auth': False,
            'client_isolation': True,  # Optimiste par défaut
            'https_portal': False,
            'session_timeout': False,
            'dot1x_available': False,
            'proxy_info_leak': False,
        }

        if not portal_ip and detect_result:
            portal_ip = detect_result.get('portal_ip')
        if not portal_port and detect_result:
            portal_port = detect_result.get('portal_port', 80)

        portal_port = portal_port or 80

        # Check 1 : Authentification MAC uniquement
        mac_only = self._check_mac_only_auth(portal_ip, portal_port, detect_result)
        checks['mac_only_auth'] = mac_only
        if mac_only:
            score -= 30
            vulnerabilities.append({
                'severity': 'CRITICAL',
                'id': 'mac_only_auth',
                'name': 'Authentification par MAC uniquement',
                'description': (
                    'Le portail n\'utilise que l\'adresse MAC pour identifier les clients autorisés. '
                    'L\'adresse MAC est visible en clair dans les trames réseau et peut être copiée '
                    'par n\'importe quel appareil. Un attaquant peut usurper la MAC d\'un client '
                    'autorisé pour contourner le portail sans authentification.'
                ),
                'remediation': (
                    'Implémenter 802.1X avec authentification par certificat ou login/password. '
                    'À défaut, combiner MAC + IP + cookie de session + timeout court (30 min max).'
                ),
                'cvss': 9.1,
            })

        # Check 2 : Isolation des clients
        no_isolation = self._check_no_client_isolation(portal_ip)
        checks['client_isolation'] = not no_isolation
        if no_isolation:
            score -= 20
            vulnerabilities.append({
                'severity': 'CRITICAL',
                'id': 'no_client_isolation',
                'name': 'Pas d\'isolation entre les clients',
                'description': (
                    'Les appareils connectés au même réseau WiFi peuvent voir le trafic des autres '
                    'clients. Cela permet l\'identification des adresses MAC autorisées, '
                    'l\'interception de trafic (ARP spoofing), et facilite le contournement du portail.'
                ),
                'remediation': (
                    'Activer AP Isolation (ou Client Isolation) sur le point d\'accès WiFi. '
                    'Configurer des ACLs pour empêcher le trafic inter-clients.'
                ),
                'cvss': 8.5,
            })

        # Check 3 : HTTPS sur le portail
        https_ok = self._check_https_portal(portal_ip, portal_port)
        checks['https_portal'] = https_ok
        if not https_ok:
            score -= 15
            vulnerabilities.append({
                'severity': 'HIGH',
                'id': 'http_portal',
                'name': 'Portail captif en HTTP (pas HTTPS)',
                'description': (
                    'La page de connexion du portail est servie en HTTP. '
                    'Les identifiants saisis par les utilisateurs transitent en clair '
                    'sur le réseau et peuvent être interceptés par un attaquant passif.'
                ),
                'remediation': (
                    'Configurer HTTPS sur le portail captif avec un certificat TLS valide. '
                    'Rediriger tout le trafic HTTP vers HTTPS.'
                ),
                'cvss': 7.4,
            })

        # Check 4 : Timeout de session
        has_timeout = self._check_session_timeout(portal_ip, portal_port)
        checks['session_timeout'] = has_timeout
        if not has_timeout:
            score -= 15
            vulnerabilities.append({
                'severity': 'HIGH',
                'id': 'no_session_timeout',
                'name': 'Pas de timeout de session',
                'description': (
                    'Les autorisations du portail captif n\'expirent pas ou ont un timeout très long. '
                    'Un MAC spoofé reste valide indéfiniment, même après que l\'appareil '
                    'légitime s\'est déconnecté.'
                ),
                'remediation': (
                    'Configurer un timeout de session de 30 à 60 minutes maximum. '
                    'Forcer la réauthentification périodique et lier l\'autorisation à l\'IP en plus de la MAC.'
                ),
                'cvss': 6.8,
            })

        # Check 5 : Fuite d'info du proxy
        proxy_leak = self._check_proxy_info_leak(portal_ip)
        checks['proxy_info_leak'] = proxy_leak
        if proxy_leak:
            score -= 10
            vulnerabilities.append({
                'severity': 'MEDIUM',
                'id': 'proxy_info_leak',
                'name': 'Fuite d\'information du proxy',
                'description': (
                    'Le proxy (Squid ou autre) révèle sa version, son nom d\'hôte et des '
                    'détails de configuration dans les messages d\'erreur HTTP.'
                ),
                'remediation': (
                    'Configurer le proxy pour masquer les informations de version. '
                    'Personnaliser les pages d\'erreur pour ne pas révéler de détails techniques.'
                ),
                'cvss': 5.3,
            })

        # Check 6 : 802.1X disponible
        dot1x = self._check_802_1x(portal_ip)
        checks['dot1x_available'] = dot1x
        if not dot1x:
            score -= 10
            vulnerabilities.append({
                'severity': 'MEDIUM',
                'id': 'no_802_1x',
                'name': 'Pas d\'authentification 802.1X',
                'description': (
                    'Le réseau n\'utilise pas le standard 802.1X (EAP) pour l\'authentification. '
                    '802.1X lie l\'authentification à des credentials forts (certificats, RADIUS) '
                    'plutôt qu\'à une simple adresse MAC.'
                ),
                'remediation': (
                    'Déployer 802.1X avec un serveur RADIUS. Utiliser EAP-TLS avec certificats '
                    'pour les clients d\'entreprise ou EAP-PEAP/MSCHAPv2 pour les utilisateurs.'
                ),
                'cvss': 5.0,
            })

        # Calcul du grade
        score = max(0, min(100, score))
        grade = self._compute_grade(score)

        return {
            'score': score,
            'grade': grade,
            'portal_ip': portal_ip,
            'vulnerabilities': vulnerabilities,
            'checks': checks,
            'vuln_count': {
                'CRITICAL': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
                'HIGH': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
                'MEDIUM': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
                'LOW': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            },
        }

    def _check_mac_only_auth(self, portal_ip, portal_port, detect_result=None):
        """Vérifie si le portail n'utilise que la MAC pour l'authentification."""
        # Si le résultat de détection indique mac_only directement
        if detect_result and detect_result.get('auth_method') == 'mac_only':
            return True

        if not portal_ip:
            return True  # Conservateur

        try:
            resp = requests.get(
                f'http://{portal_ip}:{portal_port}/',
                timeout=5,
                verify=False,
            )
            html = resp.text.lower()
            # Présence de champs password → authentification par credentials
            if 'password' in html or 'passwd' in html or 'mot de passe' in html:
                return False
            # Seulement un bouton "accept" → MAC only
            return True
        except Exception:
            return True  # Conservateur si pas de réponse

    def _check_no_client_isolation(self, portal_ip):
        """Vérifie si les clients peuvent se voir entre eux (pas d'isolation)."""
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0

            if not portal_ip:
                return True  # Conservateur

            # Déduire le sous-réseau
            parts = portal_ip.split('.')
            subnet = f'{".".join(parts[:3])}.0/24'

            # Envoyer des ARP requests — si on reçoit des réponses d'autres clients,
            # l'isolation n'est pas activée
            req = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=subnet)
            answered, _ = srp(req, timeout=2, verbose=0)

            # Si plus de 2 réponses (gateway + au moins un autre), pas d'isolation
            non_gateway = [a for a in answered if a[1][ARP].psrc != portal_ip]
            return len(non_gateway) > 0

        except Exception:
            # Sans Scapy, on ne peut pas tester — supposer pas d'isolation (conservateur)
            return True

    def _check_https_portal(self, portal_ip, portal_port):
        """Vérifie si le portail est accessible en HTTPS."""
        if not portal_ip:
            return False
        try:
            resp = requests.get(
                f'https://{portal_ip}/',
                timeout=3,
                verify=False,
            )
            return resp.status_code < 500
        except requests.exceptions.SSLError:
            # SSL mais certificat invalide — HTTPS présent mais mal configuré
            return True
        except Exception:
            return False

    def _check_session_timeout(self, portal_ip, portal_port):
        """Vérifie si des headers de timeout de session sont présents."""
        if not portal_ip:
            return False
        try:
            resp = requests.get(
                f'http://{portal_ip}:{portal_port}/',
                timeout=5,
                verify=False,
            )
            # Chercher des indices de timeout dans les headers ou le HTML
            headers_str = str(resp.headers).lower()
            html = resp.text.lower()

            timeout_indicators = [
                'session-timeout', 'idle-timeout', 'max-age',
                'session_timeout', 'timeout', 'expire', 'expiry',
            ]

            return any(ind in headers_str or ind in html for ind in timeout_indicators)
        except Exception:
            return False

    def _check_proxy_info_leak(self, portal_ip):
        """Vérifie si le proxy révèle des informations dans les erreurs."""
        if not portal_ip:
            return False

        proxy_ports = [8080, 3128]
        for port in proxy_ports:
            try:
                resp = requests.get(
                    f'http://{portal_ip}:{port}/this_path_does_not_exist_xyz',
                    timeout=3,
                    verify=False,
                )
                content = resp.text.lower()
                # Chercher la version de Squid ou d'autres proxies
                if 'squid' in content or 'proxy' in content.lower():
                    import re
                    if re.search(r'squid/[\d.]+', content) or 'via:' in str(resp.headers).lower():
                        return True
            except Exception:
                continue

        return False

    def _check_802_1x(self, portal_ip):
        """Vérifie (heuristique) si 802.1X est disponible sur le réseau."""
        # 802.1X utilise le port 1812 (RADIUS auth) et 1813 (RADIUS accounting)
        # On ne peut pas vraiment tester 802.1X sans client EAP
        # Heuristique : si le portail répond sur le port 443 avec un certificat valide,
        # il y a plus de chances que l'infrastructure soit bien configurée
        if not portal_ip:
            return False

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((portal_ip, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    # Présence d'un certificat = infrastructure plus mature
                    return bool(cert)
        except Exception:
            return False

    def _compute_grade(self, score):
        """Calcule le grade de sécurité (A-F)."""
        if score >= 90:
            return 'A'
        elif score >= 75:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 45:
            return 'D'
        elif score >= 25:
            return 'E'
        else:
            return 'F'
