# portal_mac_spoofer.py — MAC spoofing Windows via le registre
# Change l'adresse MAC d'un adaptateur réseau pour bypasser un portail captif

import atexit
import os
import re
import subprocess
import sys
import threading
import time
import winreg


# Fichier de sauvegarde de la MAC originale
_BACKUP_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'mac_backup.txt')

# Clé de registre des adaptateurs réseau
_ADAPTER_KEY = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'


class MacSpoofError(Exception):
    pass


class PortalMacSpoofer:
    """
    Change l'adresse MAC d'un adaptateur réseau Windows via le registre.

    Processus :
    1. Sauvegarder la MAC originale
    2. Trouver la clé de registre de l'adaptateur
    3. Écrire la nouvelle MAC dans NetworkAddress
    4. Désactiver l'adaptateur via netsh
    5. Réactiver l'adaptateur
    6. Renouveler le bail DHCP
    7. Vérifier que la MAC a bien changé
    8. Tester l'accès Internet

    Restauration automatique à l'arrêt via atexit.
    """

    def __init__(self, events=None):
        self.events = events
        self._original_mac = None
        self._current_interface = None
        self._spoofed = False
        atexit.register(self._restore_on_exit)

    def get_current_mac(self):
        """Retourne la MAC actuelle et les infos de l'interface principale."""
        try:
            interface_name, mac = self._get_main_interface()
            original = self._load_backup_mac() or mac
            return {
                'mac': mac,
                'interface': interface_name,
                'original_mac': original,
                'is_spoofed': self._spoofed or (mac != original and original is not None),
            }
        except Exception as e:
            return {
                'mac': None,
                'interface': None,
                'original_mac': None,
                'is_spoofed': False,
                'error': str(e),
            }

    def spoof(self, target_mac, renew_dhcp=True, test_internet=True):
        """
        Change la MAC vers target_mac.
        Émet des événements portal:spoof_progress pendant le processus.
        Retourne un dict avec le résultat.
        """
        self._check_admin()

        # Formater la MAC cible
        target_mac_clean = self._format_mac(target_mac)
        if not target_mac_clean:
            raise MacSpoofError(f'MAC invalide : {target_mac}')

        result = {
            'success': False,
            'old_mac': None,
            'new_mac': None,
            'new_ip': None,
            'internet_access': False,
            'error': None,
        }

        try:
            # Étape 1 : Récupérer l'interface et la MAC actuelle
            self._emit_progress('reading_interface', True, 'Lecture de l\'interface réseau...')
            interface_name, current_mac = self._get_main_interface()
            self._current_interface = interface_name
            result['old_mac'] = current_mac

            # Sauvegarder la MAC originale
            if not self._original_mac:
                self._original_mac = current_mac
                self._save_backup_mac(current_mac)
            self._emit_progress('backup_saved', True, f'MAC originale sauvegardée : {current_mac}')

            # Étape 2 : Trouver la clé de registre
            self._emit_progress('finding_registry', True, 'Recherche de la clé de registre...')
            reg_key_path = self._find_adapter_key(interface_name)
            if not reg_key_path:
                raise MacSpoofError(f'Adaptateur non trouvé dans le registre : {interface_name}')

            # Étape 3 : Écrire la nouvelle MAC dans le registre
            self._emit_progress('writing_registry', True, f'Écriture registre : {target_mac_clean}')
            self._write_mac_to_registry(reg_key_path, target_mac_clean)

            # Étape 4 : Désactiver l'adaptateur
            self._emit_progress('disabling_adapter', True, 'Désactivation de l\'adaptateur réseau...')
            self._disable_adapter(interface_name)
            time.sleep(1)

            # Étape 5 : Réactiver l'adaptateur
            self._emit_progress('restarting_adapter', True, 'Redémarrage de la carte réseau...')
            self._enable_adapter(interface_name)
            time.sleep(3)

            # Vérifier que la carte est bien active
            self._wait_for_adapter(interface_name, timeout=10)
            self._emit_progress('adapter_up', True, 'Carte réseau active')
            self._spoofed = True

            # Étape 6 : Renouveler l'IP via DHCP
            new_ip = None
            if renew_dhcp:
                self._emit_progress('renewing_dhcp', True, 'Renouvellement DHCP...')
                new_ip = self._renew_dhcp()
                if new_ip:
                    self._emit_progress('dhcp_done', True, f'Nouvelle IP : {new_ip}')
                else:
                    self._emit_progress('dhcp_done', False, 'DHCP échoué — pas de nouvelle IP')

            result['new_ip'] = new_ip

            # Vérifier que la MAC a bien changé
            _, actual_mac = self._get_main_interface()
            result['new_mac'] = actual_mac
            if actual_mac.upper().replace('-', ':') != target_mac_clean.upper():
                self._emit_progress('verify_mac', False, f'MAC après changement : {actual_mac} (attendu : {target_mac_clean})')
            else:
                self._emit_progress('verify_mac', True, f'MAC changée avec succès : {actual_mac}')

            # Étape 7 : Tester l'accès Internet
            internet_ok = False
            if test_internet:
                self._emit_progress('testing_internet', True, 'Test d\'accès Internet...')
                internet_ok = self._test_internet()
                if internet_ok:
                    self._emit_progress('internet_ok', True, 'Test Internet ✓ BYPASS RÉUSSI')
                else:
                    self._emit_progress('internet_fail', False, 'Pas d\'accès Internet — bypass échoué')

            result['internet_access'] = internet_ok
            result['success'] = True

            # Émettre le résultat final
            if self.events:
                self.events.emit('portal:spoof_result', {
                    'success': True,
                    'internet_access': internet_ok,
                    'new_mac': result['new_mac'],
                    'new_ip': new_ip,
                })

        except MacSpoofError as e:
            result['error'] = str(e)
            result['success'] = False
            if self.events:
                self.events.emit('portal:spoof_result', {
                    'success': False,
                    'error': str(e),
                })
        except Exception as e:
            result['error'] = str(e)
            result['success'] = False
            if self.events:
                self.events.emit('portal:spoof_result', {
                    'success': False,
                    'error': str(e),
                })

        return result

    def restore(self):
        """Restaure la MAC originale."""
        original = self._original_mac or self._load_backup_mac()
        if not original:
            return {'success': False, 'error': 'Pas de MAC originale sauvegardée'}

        try:
            self._check_admin()
            interface_name = self._current_interface
            if not interface_name:
                interface_name, _ = self._get_main_interface()

            # Trouver la clé registre
            reg_key_path = self._find_adapter_key(interface_name)
            if reg_key_path:
                # Supprimer la valeur NetworkAddress → retour à la MAC d'usine
                self._delete_mac_from_registry(reg_key_path)

            # Redémarrer l'adaptateur
            self._disable_adapter(interface_name)
            time.sleep(1)
            self._enable_adapter(interface_name)
            time.sleep(3)

            self._spoofed = False
            self._delete_backup_mac()

            _, restored_mac = self._get_main_interface()
            return {'success': True, 'restored_mac': restored_mac}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _check_admin(self):
        """Vérifie que le script tourne en tant qu'administrateur."""
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise MacSpoofError('Droits administrateur requis pour le MAC spoofing')
        except AttributeError:
            pass  # Non-Windows, ignore

    def _get_main_interface(self):
        """Retourne (nom_interface, mac_actuelle) de l'adaptateur principal."""
        result = subprocess.run(
            ['getmac', '/fo', 'csv', '/v'],
            capture_output=True,
            text=True,
            timeout=10,
        )

        lines = result.stdout.strip().splitlines()
        # Ignorer l'en-tête CSV
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 4:
                connection_name = parts[0]
                network_adapter = parts[1]
                physical_addr = parts[2]
                transport_name = parts[3]

                # Ignorer les adaptateurs virtuels et loopback
                if any(skip in connection_name.lower() for skip in ['loopback', 'pseudo', 'miniport']):
                    continue
                if any(skip in network_adapter.lower() for skip in ['teredo', 'isatap', '6to4']):
                    continue

                # Nettoyer la MAC (format XX-XX-XX-XX-XX-XX → XX:XX:XX:XX:XX:XX)
                mac = physical_addr.replace('-', ':').upper()
                if mac and mac != 'N/A':
                    return connection_name, mac

        # Fallback via ipconfig
        return self._get_interface_via_ipconfig()

    def _get_interface_via_ipconfig(self):
        """Fallback : récupère l'interface via ipconfig."""
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=10)
        current_adapter = None
        for line in result.stdout.splitlines():
            # Nom de l'adaptateur
            if line and not line.startswith(' '):
                match = re.match(r'(.+?)\s*:', line)
                if match:
                    current_adapter = match.group(1).strip()

            # MAC
            if 'Adresse physique' in line or 'Physical Address' in line:
                match = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', line)
                if match and current_adapter:
                    mac = match.group(1).replace('-', ':').upper()
                    return current_adapter, mac

        raise MacSpoofError('Impossible de trouver l\'interface réseau principale')

    def _find_adapter_key(self, interface_name):
        """Trouve la clé de registre de l'adaptateur réseau."""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _ADAPTER_KEY)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f'{_ADAPTER_KEY}\\{subkey_name}'

                    try:
                        subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
                        try:
                            driver_desc, _ = winreg.QueryValueEx(subkey, 'DriverDesc')
                            # Correspondance approximative avec le nom d'interface
                            if (interface_name.lower() in driver_desc.lower() or
                                    driver_desc.lower() in interface_name.lower()):
                                winreg.CloseKey(subkey)
                                winreg.CloseKey(key)
                                return subkey_path
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(subkey)
                    except Exception:
                        pass

                    i += 1
                except OSError:
                    break

            winreg.CloseKey(key)
        except Exception as e:
            raise MacSpoofError(f'Erreur accès registre : {e}')

        # Si pas trouvé par nom, prendre le premier adaptateur avec une adresse MAC
        return self._find_any_adapter_key()

    def _find_any_adapter_key(self):
        """Trouve n'importe quel adaptateur réseau dans le registre."""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _ADAPTER_KEY)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f'{_ADAPTER_KEY}\\{subkey_name}'
                    try:
                        subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
                        try:
                            winreg.QueryValueEx(subkey, 'DriverDesc')
                            winreg.CloseKey(subkey)
                            winreg.CloseKey(key)
                            return subkey_path
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(subkey)
                    except Exception:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
        return None

    def _write_mac_to_registry(self, key_path, mac):
        """Écrit la MAC dans la clé de registre NetworkAddress."""
        mac_no_sep = mac.replace(':', '').replace('-', '').upper()
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, 'NetworkAddress', 0, winreg.REG_SZ, mac_no_sep)
            winreg.CloseKey(key)
        except PermissionError:
            raise MacSpoofError('Permission refusée — lancez en tant qu\'administrateur')
        except Exception as e:
            raise MacSpoofError(f'Erreur écriture registre : {e}')

    def _delete_mac_from_registry(self, key_path):
        """Supprime NetworkAddress du registre (restaure la MAC d'usine)."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                winreg.DeleteValue(key, 'NetworkAddress')
            except FileNotFoundError:
                pass  # La valeur n'existait pas
            winreg.CloseKey(key)
        except Exception as e:
            raise MacSpoofError(f'Erreur suppression registre : {e}')

    def _disable_adapter(self, interface_name):
        """Désactive l'adaptateur réseau via netsh."""
        subprocess.run(
            ['netsh', 'interface', 'set', 'interface', interface_name, 'admin=disable'],
            capture_output=True,
            timeout=15,
        )

    def _enable_adapter(self, interface_name):
        """Réactive l'adaptateur réseau via netsh."""
        subprocess.run(
            ['netsh', 'interface', 'set', 'interface', interface_name, 'admin=enable'],
            capture_output=True,
            timeout=15,
        )

    def _wait_for_adapter(self, interface_name, timeout=15):
        """Attend que l'adaptateur soit actif."""
        start = time.time()
        while time.time() - start < timeout:
            result = subprocess.run(
                ['netsh', 'interface', 'show', 'interface', interface_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if 'Connecté' in result.stdout or 'Connected' in result.stdout:
                return True
            time.sleep(1)
        return False

    def _renew_dhcp(self):
        """Renouvelle le bail DHCP et retourne la nouvelle IP."""
        try:
            subprocess.run(['ipconfig', '/release'], capture_output=True, timeout=15)
            time.sleep(1)
            subprocess.run(['ipconfig', '/renew'], capture_output=True, timeout=30)
            time.sleep(2)

            # Récupérer la nouvelle IP
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                if 'IPv4' in line or 'Adresse IPv4' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        if not ip.startswith('169.'):  # Pas APIPA
                            return ip
        except Exception:
            pass
        return None

    def _test_internet(self):
        """Teste l'accès Internet."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _format_mac(self, mac):
        """Normalise une adresse MAC au format XX:XX:XX:XX:XX:XX."""
        clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
        if len(clean) != 12:
            return None
        return ':'.join(clean[i:i+2].upper() for i in range(0, 12, 2))

    def _save_backup_mac(self, mac):
        """Sauvegarde la MAC originale dans un fichier."""
        try:
            os.makedirs(os.path.dirname(_BACKUP_FILE), exist_ok=True)
            with open(_BACKUP_FILE, 'w') as f:
                f.write(mac)
        except Exception:
            pass

    def _load_backup_mac(self):
        """Charge la MAC sauvegardée."""
        try:
            if os.path.exists(_BACKUP_FILE):
                with open(_BACKUP_FILE, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return None

    def _delete_backup_mac(self):
        """Supprime le fichier de sauvegarde."""
        try:
            if os.path.exists(_BACKUP_FILE):
                os.remove(_BACKUP_FILE)
        except Exception:
            pass

    def _emit_progress(self, step, success, message):
        """Émet un événement de progression."""
        if self.events:
            self.events.emit('portal:spoof_progress', {
                'step': step,
                'success': success,
                'message': message,
            })

    def _restore_on_exit(self):
        """Restauration automatique à la fermeture du programme."""
        if self._spoofed:
            try:
                self.restore()
            except Exception:
                pass
