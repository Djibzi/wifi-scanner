# routes_report.py — Routes API pour les rapports

import os
import tempfile

from flask import Blueprint, jsonify, send_file

report_bp = Blueprint('report', __name__)


def _get_scan_state():
    from api.routes_scan import _scan_state
    return _scan_state


@report_bp.route('/report')
def get_report_data():
    # Données du rapport (pour affichage frontend)
    state = _get_scan_state()
    result = state.get('result')
    if not result:
        return jsonify({'error': 'Aucun scan disponible'}), 404

    hosts = result.hosts or []
    all_vulns = list(result.vulnerabilities)
    for host in hosts:
        all_vulns.extend(host.vulnerabilities)

    vuln_counts = {}
    from core.models import Severity
    for s in Severity:
        count = sum(1 for v in all_vulns if v.severity == s)
        if result.wifi_info:
            count += sum(1 for v in result.wifi_info.vulnerabilities if v.severity == s)
        vuln_counts[s.value] = count

    return jsonify({
        'score': result.get_security_score(),
        'grade': result.get_grade(),
        'hosts_count': len(hosts),
        'vulns_total': len(all_vulns),
        'vuln_counts': vuln_counts,
        'scan_mode': result.scan_mode,
        'scan_start': result.scan_start,
        'scan_end': result.scan_end,
    })


@report_bp.route('/report/export/<fmt>')
def export_report(fmt):
    # Exporter le rapport dans un format donné
    state = _get_scan_state()
    result = state.get('result')
    if not result:
        return jsonify({'error': 'Aucun scan disponible'}), 404

    if fmt not in ('html', 'md', 'json', 'pdf'):
        return jsonify({'error': f'Format inconnu : {fmt}'}), 400

    # Générer le rapport
    from reports.generator import ReportGenerator
    generator = ReportGenerator()
    ext = fmt if fmt != 'pdf' else 'html'
    output = os.path.join(tempfile.gettempdir(), f'redshield_report.{ext}')
    generator.generate(result, output_file=output, report_format=ext)

    mime_types = {
        'html': 'text/html',
        'md': 'text/markdown',
        'json': 'application/json',
        'pdf': 'application/pdf',
    }

    return send_file(
        output,
        mimetype=mime_types.get(fmt, 'text/plain'),
        as_attachment=True,
        download_name=f'redshield_report.{ext}',
    )
