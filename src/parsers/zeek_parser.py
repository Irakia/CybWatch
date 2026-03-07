"""
Zeek Log Parser

parses Zeek log files into Python dictionaries for the database
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class ZeekParser:
    """Parser for Zeek TSV log files."""
    
    # Default conn.log fields
    CONN_LOG_FIELDS = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
        "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"
    ]
    
    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("/opt/zeek/logs/current")
    
    def parse_line(self, line: str, fields: List[str]) -> Optional[Dict[str, Any]]:
        """Parse a single TSV line."""
        if line.startswith("#") or not line.strip():
            return None
        
        parts = line.strip().split("\t")
        if len(parts) != len(fields):
            return None
        
        record = {}
        for field, value in zip(fields, parts):
            if value == "-" or value == "(empty)":
                record[field] = None
            else:
                record[field] = value
        
        return record
    
    def _convert_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Convert Zeek epoch timestamp to datetime."""
        try:
            return datetime.fromtimestamp(float(ts_str))
        except (ValueError, TypeError):
            return None
    
    def _convert_int(self, value: Any) -> Optional[int]:
        """Safely convert to int."""
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None
    
    def _convert_float(self, value: Any) -> Optional[float]:
        """Safely convert to float."""
        try:
            return float(value) if value is not None else None
        except (ValueError, TypeError):
            return None
    
    def parse_conn_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw record to normalized format."""
        return {
            "uid": record.get("uid"),
            "timestamp": self._convert_timestamp(record.get("ts")),
            "src_ip": record.get("id.orig_h"),
            "src_port": self._convert_int(record.get("id.orig_p")),
            "dst_ip": record.get("id.resp_h"),
            "dst_port": self._convert_int(record.get("id.resp_p")),
            "protocol": record.get("proto"),
            "service": record.get("service"),
            "duration": self._convert_float(record.get("duration")),
            "bytes_sent": self._convert_int(record.get("orig_bytes")),
            "bytes_received": self._convert_int(record.get("resp_bytes")),
            "conn_state": record.get("conn_state"),
        }
    
    def parse_conn_log(self, filepath: Path = None) -> List[Dict[str, Any]]:
        """Parse conn.log and return list of connections."""
        if filepath is None:
            filepath = self.log_dir / "conn.log"
        
        if not filepath.exists():
            return []
        
        connections = []
        fields = None
        
        with open(filepath, "r") as f:
            for line in f:
                # Get field names from headear
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                elif line.startswith("#"):
                    continue
                
                if fields is None:
                    fields = self.CONN_LOG_FIELDS
                
                record = self.parse_line(line, fields)
                if record:
                    normalized = self.parse_conn_record(record)
                    if normalized.get("timestamp"):
                        connections.append(normalized)
        
        return connections
