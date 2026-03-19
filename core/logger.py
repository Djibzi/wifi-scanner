# logger.py — Système de logging du scanner réseau WiFi

import logging
import os
from datetime import datetime


class ScannerLogger:
    # Gère le logging avec sortie console (rich) et fichier

    # Niveaux de log avec couleurs pour rich
    LEVEL_COLORS = {
        "DEBUG": "dim",
        "INFO": "blue",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold red",
    }

    def __init__(self, name="wifi-scanner", log_dir=None, verbose=False, debug=False):
        self.name = name
        self.verbose = verbose
        self.debug = debug

        # Créer le logger Python standard
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.logger.handlers.clear()

        # Handler console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING))
        console_format = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%H:%M:%S")
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)

        # Handler fichier
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)

        log_filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(os.path.join(log_dir, log_filename), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter("[%(asctime)s] %(levelname)-8s [%(module)s] %(message)s")
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

    def success(self, message):
        # Log de succès affiché comme INFO avec préfixe
        self.logger.info(f"[OK] {message}")

    def vuln(self, severity, message):
        # Log spécifique pour les vulnérabilités détectées
        self.logger.warning(f"[VULN:{severity}] {message}")

    def scan_start(self, scan_type):
        # Log le début d'un scan
        self.logger.info(f"--- Début du scan : {scan_type} ---")

    def scan_end(self, scan_type, duration=None):
        # Log la fin d'un scan
        if duration:
            self.logger.info(f"--- Fin du scan : {scan_type} (durée: {duration:.2f}s) ---")
        else:
            self.logger.info(f"--- Fin du scan : {scan_type} ---")

    def host_found(self, ip, mac="", vendor=""):
        # Log la découverte d'un hôte
        parts = [f"Hôte découvert : {ip}"]
        if mac:
            parts.append(f"MAC={mac}")
        if vendor:
            parts.append(f"({vendor})")
        self.logger.info(" ".join(parts))

    def port_found(self, ip, port, service=""):
        # Log un port ouvert
        msg = f"Port ouvert : {ip}:{port}"
        if service:
            msg += f" ({service})"
        self.logger.info(msg)
