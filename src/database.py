"""
Cybwatch Database

SQLite schema / query methods
"""

import aiosqlite
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from .config import settings


# Database schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    vendor TEXT,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_known BOOLEAN NOT NULL DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT,
    duration REAL,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    conn_state TEXT,
    service TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    rule_name TEXT NOT NULL,
    description TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    raw_data TEXT,
    acknowledged BOOLEAN NOT NULL DEFAULT 0,
    acknowledged_at DATETIME
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_type TEXT NOT NULL,
    targets TEXT NOT NULL,
    duration_seconds REAL,
    hosts_found INTEGER,
    results_summary TEXT
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    severity TEXT NOT NULL DEFAULT 'medium',
    rule_type TEXT NOT NULL,
    config TEXT
);

CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp);
CREATE INDEX IF NOT EXISTS idx_connections_src_ip ON connections(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
"""

# default detection rules
DEFAULT_RULES = [
    {
        "name": "port_scan_detection",
        "description": "Detect port scanning behavior",
        "severity": "high",
        "rule_type": "port_scan",
        "config": '{"threshold": 10, "window_seconds": 60}'
    },
    {
        "name": "new_device_alert",
        "description": "Alert on new devices",
        "severity": "medium",
        "rule_type": "new_device",
        "config": '{}'
    },
    {
        "name": "suspicious_port_connection",
        "description": "Alert on suspicious ports",
        "severity": "high",
        "rule_type": "port_match",
        "config": '{"ports": [22, 23, 3389, 445, 135, 139]}'
    }
]


class Database:
    """Async SQLite database"""
    
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or settings.database_path
        self._connection: Optional[aiosqlite.Connection] = None
    
    async def connect(self) -> None:
        """Open database and create tables."""
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(SCHEMA)
        await self._connection.commit()
        await self._seed_default_rules()
    
    async def disconnect(self) -> None:
        """Close database."""
        if self._connection:
            await self._connection.close()
            self._connection = None
    
    async def _seed_default_rules(self) -> None:
        """Insert default rules if none exist."""
        cursor = await self._connection.execute("SELECT COUNT(*) FROM detection_rules")
        row = await cursor.fetchone()
        if row[0] == 0:
            for rule in DEFAULT_RULES:
                await self._connection.execute(
                    "INSERT INTO detection_rules (name, description, severity, rule_type, config) VALUES (?, ?, ?, ?, ?)",
                    (rule["name"], rule["description"], rule["severity"], rule["rule_type"], rule["config"])
                )
            await self._connection.commit()
    
    # devices
    
    async def upsert_device(self, mac_address: str, ip_address: str = None,
                           hostname: str = None, vendor: str = None) -> int:
        """Insert or update a device."""
        now = datetime.utcnow().isoformat()
        mac = mac_address.upper()
        
        cursor = await self._connection.execute(
            "SELECT id FROM devices WHERE mac_address = ?", (mac,)
        )
        row = await cursor.fetchone()
        
        if row:
            await self._connection.execute(
                "UPDATE devices SET ip_address = COALESCE(?, ip_address), hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor), last_seen = ? WHERE mac_address = ?",
                (ip_address, hostname, vendor, now, mac)
            )
            await self._connection.commit()
            return row[0]
        else:
            cursor = await self._connection.execute(
                "INSERT INTO devices (mac_address, ip_address, hostname, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (mac, ip_address, hostname, vendor, now, now)
            )
            await self._connection.commit()
            return cursor.lastrowid
    
    async def get_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all devices."""
        cursor = await self._connection.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def mark_device_known(self, device_id: int, is_known: bool = True) -> None:
        """Mark device as known/unknown."""
        await self._connection.execute(
            "UPDATE devices SET is_known = ? WHERE id = ?", (is_known, device_id)
        )
        await self._connection.commit()
    
    # connections
    
    async def insert_connections_batch(self, connections: List[Dict[str, Any]]) -> int:
        """Insert multiple connections."""
        await self._connection.executemany(
            "INSERT OR IGNORE INTO connections (uid, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, duration, bytes_sent, bytes_received, conn_state, service) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(c.get("uid"), c.get("timestamp"), c.get("src_ip"), c.get("src_port"),
              c.get("dst_ip"), c.get("dst_port"), c.get("protocol"), c.get("duration"),
              c.get("bytes_sent"), c.get("bytes_received"), c.get("conn_state"),
              c.get("service")) for c in connections]
        )
        await self._connection.commit()
        return len(connections)
    
    async def get_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent connections."""
        cursor = await self._connection.execute(
            "SELECT * FROM connections ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    # alerts
    
    async def create_alert(self, severity: str, rule_name: str, description: str,
                          source_ip: str = None, destination_ip: str = None) -> int:
        """Create an alert."""
        cursor = await self._connection.execute(
            "INSERT INTO alerts (severity, rule_name, description, source_ip, destination_ip) VALUES (?, ?, ?, ?, ?)",
            (severity, rule_name, description, source_ip, destination_ip)
        )
        await self._connection.commit()
        return cursor.lastrowid
    
    async def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        cursor = await self._connection.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def acknowledge_alert(self, alert_id: int) -> None:
        """Acknowledge an alert."""
        await self._connection.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), alert_id)
        )
        await self._connection.commit()
    
    # detection rules
    
    async def get_detection_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Get detection rules."""
        query = "SELECT * FROM detection_rules"
        if enabled_only:
            query += " WHERE enabled = 1"
        cursor = await self._connection.execute(query)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    # scans
    
    async def record_scan(self, scan_type: str, targets: str,
                         duration_seconds: float = None, hosts_found: int = None,
                         results_summary: str = None) -> int:
        """Record an Nmap scan."""
        cursor = await self._connection.execute(
            "INSERT INTO scans (scan_type, targets, duration_seconds, hosts_found, results_summary) VALUES (?, ?, ?, ?, ?)",
            (scan_type, targets, duration_seconds, hosts_found, results_summary)
        )
        await self._connection.commit()
        return cursor.lastrowid



db = Database()


async def get_db() -> Database:
    """get database."""
    return db
