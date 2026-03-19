# generator.py — Moteur de génération de rapports
# Génère les rapports HTML, Markdown et JSON à partir des résultats de scan

import os
import json
from datetime import datetime

from core.models import ScanResult, Severity
from core.config import ScannerConfig


class ReportGenerator:
    # Génère les rapports de sécurité dans différents formats

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger
        self.templates_dir = os.path.join(os.path.dirname(__file__), "templates")

    def generate(self, result, output_file=None, report_format=None):
        # Génère le rapport dans le format demandé
        fmt = report_format or self.config.report_format
        output = output_file or self.config.output_file

        # Nom de fichier par défaut
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = {"html": "html", "md": "md", "json": "json"}.get(fmt, "html")
            output = os.path.join(self.config.REPORTS_DIR, f"scan_{timestamp}.{ext}")

        # Créer le dossier si nécessaire
        os.makedirs(os.path.dirname(output) if os.path.dirname(output) else ".", exist_ok=True)

        # Préparer les données du rapport
        data = self._prepare_data(result)

        # Générer selon le format
        if fmt == "html":
            content = self._render_html(data)
        elif fmt == "md":
            content = self._render_markdown(data)
        elif fmt == "json":
            content = self._render_json(data)
        else:
            content = self._render_html(data)

        # Écrire le fichier
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)

        if self.logger:
            self.logger.success(f"Rapport généré : {output}")

        return output

    def _prepare_data(self, result):
        # Prépare toutes les données pour les templates
        wifi = result.wifi_info
        hosts = result.hosts or []

        # Collecter toutes les vulnérabilités
        all_vulns = list(result.vulnerabilities)
        for host in hosts:
            all_vulns.extend(host.vulnerabilities)

        # Trier par sévérité
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

        # Compter par sévérité
        vuln_counts = {}
        for s in Severity:
            count = sum(1 for v in all_vulns if v.severity == s)
            if wifi:
                count += sum(1 for v in wifi.vulnerabilities if v.severity == s)
            vuln_counts[s.value] = count

        # Durée du scan
        scan_duration = ""
        if result.scan_start and result.scan_end:
            try:
                start = datetime.fromisoformat(result.scan_start)
                end = datetime.fromisoformat(result.scan_end)
                duration = (end - start).total_seconds()
                scan_duration = f"{duration:.1f} secondes"
            except (ValueError, TypeError):
                scan_duration = "N/A"

        return {
            "wifi": wifi,
            "hosts": hosts,
            "all_vulns": all_vulns,
            "vuln_counts": vuln_counts,
            "score": result.get_security_score(),
            "grade": result.get_grade(),
            "scan_date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "scan_duration": scan_duration,
            "scan_mode": result.scan_mode,
        }

    # --- Rendu HTML ---

    def _render_html(self, data):
        # Rendu HTML avec Jinja2
        try:
            from jinja2 import Environment, FileSystemLoader
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            template = env.get_template("report_html.jinja2")
            return template.render(**data)
        except ImportError:
            if self.logger:
                self.logger.warning("jinja2 non installé — rapport HTML simplifié")
            return self._render_html_fallback(data)

    def _render_html_fallback(self, data):
        # HTML de secours sans Jinja2
        html = [
            "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'>",
            f"<title>Rapport WiFi Scanner</title>",
            "<style>body{font-family:sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px;max-width:900px;margin:0 auto}",
            "h1{color:#38bdf8}h2{color:#38bdf8;border-bottom:1px solid #333;padding-bottom:5px}",
            "table{width:100%;border-collapse:collapse;margin:10px 0}th,td{padding:8px;text-align:left;border-bottom:1px solid #333}",
            "th{background:#2a2a4a;color:#38bdf8}.vuln{padding:10px;margin:5px 0;border-left:4px solid #666;background:#2a2a3a}",
            ".crit{border-left-color:#ef4444}.high{border-left-color:#f97316}.med{border-left-color:#f59e0b}",
            "</style></head><body>",
        ]

        html.append(f"<h1>Rapport de Sécurité WiFi</h1>")
        html.append(f"<p>Score : <strong>{data['score']}/100 ({data['grade']})</strong></p>")
        html.append(f"<p>Date : {data['scan_date']}</p>")

        # WiFi
        wifi = data["wifi"]
        if wifi and wifi.ssid:
            html.append(f"<h2>Réseau WiFi</h2>")
            html.append(f"<p>SSID: {wifi.ssid} | Sécurité: {wifi.security}/{wifi.encryption} | Canal: {wifi.channel}</p>")

        # Hôtes
        if data["hosts"]:
            html.append(f"<h2>Appareils ({len(data['hosts'])})</h2><table>")
            html.append("<tr><th>IP</th><th>MAC</th><th>Fabricant</th><th>OS</th><th>Ports</th><th>Vulns</th></tr>")
            for h in data["hosts"]:
                ports = ", ".join(str(p.number) for p in h.open_ports)
                html.append(f"<tr><td>{h.ip}</td><td>{h.mac or '—'}</td><td>{h.vendor or '—'}</td>"
                           f"<td>{h.os_guess or '—'}</td><td>{ports or '—'}</td><td>{len(h.vulnerabilities)}</td></tr>")
            html.append("</table>")

        # Vulnérabilités
        if data["all_vulns"]:
            html.append(f"<h2>Vulnérabilités ({len(data['all_vulns'])})</h2>")
            for v in data["all_vulns"]:
                css = {"CRITIQUE": "crit", "HAUTE": "high", "MOYENNE": "med"}.get(v.severity.value, "")
                html.append(f"<div class='vuln {css}'><strong>[{v.severity.value}] {v.name}</strong>")
                html.append(f"<p>{v.description}</p>")
                html.append(f"<p><em>Remédiation : {v.remediation}</em></p></div>")

        html.append("</body></html>")
        return "\n".join(html)

    # --- Rendu Markdown ---

    def _render_markdown(self, data):
        # Rendu Markdown avec Jinja2
        try:
            from jinja2 import Environment, FileSystemLoader
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            template = env.get_template("report_md.jinja2")
            return template.render(**data)
        except ImportError:
            if self.logger:
                self.logger.warning("jinja2 non installé — rapport Markdown simplifié")
            return self._render_markdown_fallback(data)

    def _render_markdown_fallback(self, data):
        # Markdown de secours sans Jinja2
        lines = [
            f"# Rapport de Sécurité WiFi",
            f"",
            f"**Score :** {data['score']}/100 ({data['grade']})",
            f"**Date :** {data['scan_date']}",
            f"",
        ]

        if data["all_vulns"]:
            lines.append("## Vulnérabilités")
            lines.append("")
            for v in data["all_vulns"]:
                lines.append(f"- **[{v.severity.value}]** {v.name}")
                lines.append(f"  - {v.description}")
                lines.append(f"  - *Remédiation :* {v.remediation}")
                lines.append("")

        return "\n".join(lines)

    # --- Rendu JSON ---

    def _render_json(self, data):
        # Rendu JSON structuré
        output = {
            "scan": {
                "date": data["scan_date"],
                "duration": data["scan_duration"],
                "mode": data["scan_mode"],
                "score": data["score"],
                "grade": data["grade"],
            },
            "wifi": self._wifi_to_dict(data["wifi"]) if data["wifi"] else None,
            "hosts": [self._host_to_dict(h) for h in data["hosts"]],
            "vulnerabilities": [self._vuln_to_dict(v) for v in data["all_vulns"]],
            "summary": {
                "total_hosts": len(data["hosts"]),
                "total_vulnerabilities": len(data["all_vulns"]),
                "by_severity": data["vuln_counts"],
            },
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def _wifi_to_dict(self, wifi):
        # Convertit WifiInfo en dict
        if not wifi:
            return None
        return {
            "ssid": wifi.ssid,
            "bssid": wifi.bssid,
            "security": wifi.security,
            "encryption": wifi.encryption,
            "channel": wifi.channel,
            "frequency": wifi.frequency,
            "signal_strength": wifi.signal_strength,
            "gateway_ip": wifi.gateway_ip,
            "subnet_mask": wifi.subnet_mask,
            "dns_servers": wifi.dns_servers,
            "vulnerabilities": [
                {"name": v.name, "severity": v.severity.value,
                 "description": v.description, "remediation": v.remediation}
                for v in wifi.vulnerabilities
            ],
        }

    def _host_to_dict(self, host):
        # Convertit Host en dict
        return {
            "ip": host.ip,
            "mac": host.mac,
            "vendor": host.vendor,
            "hostname": host.hostname,
            "os_guess": host.os_guess,
            "device_type": host.device_type,
            "is_gateway": host.is_gateway,
            "open_ports": [
                {"number": p.number, "protocol": p.protocol.value,
                 "service": p.service, "version": p.version, "banner": p.banner}
                for p in host.open_ports
            ],
            "vulnerabilities": [self._vuln_to_dict(v) for v in host.vulnerabilities],
        }

    def _vuln_to_dict(self, vuln):
        # Convertit Vulnerability en dict
        return {
            "name": vuln.name,
            "severity": vuln.severity.value,
            "description": vuln.description,
            "remediation": vuln.remediation,
            "host_ip": vuln.host_ip,
            "port": vuln.port,
            "cve": vuln.cve,
            "proof": vuln.proof,
        }
