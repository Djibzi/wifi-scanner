# database.py — Stockage local SQLite pour l'historique des scans

import os
import json
import sqlite3
from datetime import datetime


class Database:
    # Base de données SQLite pour stocker l'historique

    def __init__(self, db_path=None):
        if db_path is None:
            db_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, 'redshield.db')
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        # Crée les tables si elles n'existent pas
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                mode TEXT NOT NULL,
                target TEXT,
                duration REAL,
                score INTEGER,
                grade TEXT,
                hosts_count INTEGER,
                vulns_count INTEGER,
                result_json TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

    def save_scan(self, result_data):
        # Sauvegarde un résultat de scan
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scans (date, mode, target, duration, score, grade,
                             hosts_count, vulns_count, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            result_data.get('mode', ''),
            result_data.get('target', ''),
            result_data.get('duration', 0),
            result_data.get('score', 0),
            result_data.get('grade', ''),
            result_data.get('hosts_count', 0),
            result_data.get('vulns_count', 0),
            json.dumps(result_data, ensure_ascii=False),
        ))

        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def get_history(self, limit=50):
        # Récupère l'historique des scans
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, date, mode, target, duration, score, grade,
                   hosts_count, vulns_count
            FROM scans ORDER BY id DESC LIMIT ?
        ''', (limit,))

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_scan(self, scan_id):
        # Récupère un scan par ID
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            data = dict(row)
            data['result'] = json.loads(data.pop('result_json', '{}'))
            return data
        return None

    def get_setting(self, key, default=None):
        # Récupère un paramètre
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        # Sauvegarde un paramètre
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
        ''', (key, json.dumps(value, ensure_ascii=False)))
        conn.commit()
        conn.close()
