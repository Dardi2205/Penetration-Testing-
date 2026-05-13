"""
APIX v3 - Database Manager
Handles all SQLite operations for targets, subdomains, endpoints, and vulnerabilities
"""

import sqlite3
import json
import csv
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".apix" / "apix.db"


class DatabaseManager:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        """Initialize all database tables"""
        cursor = self.conn.cursor()

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            ip TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            subdomain TEXT NOT NULL,
            ip TEXT,
            status_code INTEGER,
            title TEXT,
            is_alive INTEGER DEFAULT 0,
            source TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            url TEXT NOT NULL,
            method TEXT,
            status_code INTEGER,
            response_length INTEGER,
            response_time INTEGER,
            content_type TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            vuln_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            url TEXT,
            description TEXT,
            evidence TEXT,
            tool TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            record_type TEXT,
            value TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        """)
        self.conn.commit()

    # ============ TARGETS ============
    def add_target(self, domain, ip=None, notes=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO targets (domain, ip, notes) VALUES (?, ?, ?)",
                (domain, ip, notes)
            )
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error adding target: {e}")
            return None

    def get_target_id(self, domain):
        cursor = self.conn.cursor()
        row = cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        return row["id"] if row else None

    def get_all_targets(self):
        cursor = self.conn.cursor()
        return cursor.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()

    def delete_target(self, target_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        cursor.execute("DELETE FROM subdomains WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM endpoints WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM vulnerabilities WHERE target_id = ?", (target_id,))
        self.conn.commit()

    # ============ SUBDOMAINS ============
    def add_subdomain(self, target_id, subdomain, ip=None, status_code=None,
                      title=None, is_alive=0, source=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO subdomains 
                (target_id, subdomain, ip, status_code, title, is_alive, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (target_id, subdomain, ip, status_code, title, is_alive, source))
            self.conn.commit()
        except Exception as e:
            print(f"[DB] Error adding subdomain: {e}")

    def get_subdomains(self, target_id):
        cursor = self.conn.cursor()
        return cursor.execute(
            "SELECT * FROM subdomains WHERE target_id = ? ORDER BY is_alive DESC",
            (target_id,)
        ).fetchall()

    # ============ ENDPOINTS ============
    def add_endpoint(self, target_id, url, method, status_code,
                     response_length=0, response_time=0, content_type=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO endpoints
                (target_id, url, method, status_code, response_length, response_time, content_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (target_id, url, method, status_code, response_length, response_time, content_type))
            self.conn.commit()
        except Exception as e:
            print(f"[DB] Error adding endpoint: {e}")

    def get_endpoints(self, target_id):
        cursor = self.conn.cursor()
        return cursor.execute(
            "SELECT * FROM endpoints WHERE target_id = ? ORDER BY status_code",
            (target_id,)
        ).fetchall()

    # ============ VULNERABILITIES ============
    def add_vulnerability(self, target_id, vuln_type, severity, url=None,
                          description=None, evidence=None, tool=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO vulnerabilities
                (target_id, vuln_type, severity, url, description, evidence, tool)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (target_id, vuln_type, severity, url, description, evidence, tool))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error adding vulnerability: {e}")
            return None

    def get_vulnerabilities(self, target_id):
        cursor = self.conn.cursor()
        return cursor.execute("""
            SELECT * FROM vulnerabilities WHERE target_id = ?
            ORDER BY CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
        """, (target_id,)).fetchall()

    # ============ DNS ============
    def add_dns_record(self, target_id, record_type, value):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO dns_records (target_id, record_type, value) VALUES (?, ?, ?)",
                (target_id, record_type, value)
            )
            self.conn.commit()
        except Exception as e:
            print(f"[DB] Error adding DNS record: {e}")

    def get_dns_records(self, target_id):
        cursor = self.conn.cursor()
        return cursor.execute(
            "SELECT * FROM dns_records WHERE target_id = ?", (target_id,)
        ).fetchall()

    # ============ STATS ============
    def get_stats(self, target_id):
        cursor = self.conn.cursor()
        subdomains = cursor.execute(
            "SELECT COUNT(*) as c FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchone()["c"]
        endpoints = cursor.execute(
            "SELECT COUNT(*) as c FROM endpoints WHERE target_id = ?", (target_id,)
        ).fetchone()["c"]
        vulns = cursor.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE target_id = ?", (target_id,)
        ).fetchone()["c"]
        critical = cursor.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE target_id = ? AND severity = 'critical'",
            (target_id,)
        ).fetchone()["c"]
        high = cursor.execute(
            "SELECT COUNT(*) as c FROM vulnerabilities WHERE target_id = ? AND severity = 'high'",
            (target_id,)
        ).fetchone()["c"]
        return {"subdomains": subdomains, "endpoints": endpoints,
                "vulns": vulns, "critical": critical, "high": high}

    # ============ EXPORT ============
    def export_json(self, target_id, filepath):
        stats = self.get_stats(target_id)
        subdomains = [dict(r) for r in self.get_subdomains(target_id)]
        endpoints = [dict(r) for r in self.get_endpoints(target_id)]
        vulns = [dict(r) for r in self.get_vulnerabilities(target_id)]
        dns = [dict(r) for r in self.get_dns_records(target_id)]

        data = {
            "generated_at": datetime.now().isoformat(),
            "tool": "APIX v3",
            "stats": stats,
            "subdomains": subdomains,
            "endpoints": endpoints,
            "vulnerabilities": vulns,
            "dns_records": dns,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        return filepath

    def export_csv(self, target_id, filepath):
        vulns = self.get_vulnerabilities(target_id)
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Severity", "URL", "Description", "Tool", "Date"])
            for v in vulns:
                writer.writerow([v["vuln_type"], v["severity"], v["url"],
                                  v["description"], v["tool"], v["created_at"]])
        return filepath

    def close(self):
        self.conn.close()
