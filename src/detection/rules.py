"""
Cybwatch Detection Engine

checks connections/devices for suspicious activity
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict


SUSPICIOUS_PORTS = [22, 23, 135, 139, 445, 3389, 1433, 3306, 5432]


class DetectionEngine:
    """Detection rules""" 

    def __init__(self, port_scan_threshold: int = 10, port_scan_window: int = 60):
        """
        Initialize detection engine.
        
        Args:
            port_scan_threshold: Number of unique ports to trigger alert
            port_scan_window: Time window in seconds
        """
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        
        # track connection for port scan
        self._port_history: Dict[str, List[tuple]] = defaultdict(list)
    
    def check_suspicious_port(self, connection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if connection is to a suspicious port
        
        Return alert if triggered no otherwise
        """
        dst_port = connection.get("dst_port")
        
        if dst_port is None:
            return None
        
        if dst_port in SUSPICIOUS_PORTS:
            return {
                "severity": "high",
                "rule_name": "suspicious_port_connection",
                "description": f"Connection to suspicious port {dst_port}",
                "source_ip": connection.get("src_ip"),
                "destination_ip": connection.get("dst_ip"),
            }
        
        return None
    
    def check_new_device(self, mac_address: str, known_macs: List[str]) -> Optional[Dict[str, Any]]:
        """
        Check if mac address is new
        
        Returns alert if triggered no otherwise
        """
        if mac_address is None:
            return None
        
        mac_upper = mac_address.upper()
        known_upper = [m.upper() for m in known_macs]
        
        if mac_upper not in known_upper:
            return {
                "severity": "medium",
                "rule_name": "new_device_alert",
                "description": f"New device detected: {mac_address}",
                "source_ip": None,
                "destination_ip": None,
            }
        
        return None

    def check_port_scan(self, connection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if source IP is scanning multiple ports.
        
        Triggers if one IP hits more than threshold unique ports within time window.
        
        Returns alert dict if triggered, None otherwise.
        """
        src_ip = connection.get("src_ip")
        dst_port = connection.get("dst_port")
        timestamp = connection.get("timestamp")
        
        if not all([src_ip, dst_port, timestamp]):
            return None
        
        # convert timestamp to datetime if needed
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                return None
        
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.port_scan_window)
        
        # clean old entries for this IP
        self._port_history[src_ip] = [
            (ts, port) for ts, port in self._port_history[src_ip]
            if ts > cutoff
        ]
        
        # add current connection
        self._port_history[src_ip].append((timestamp, dst_port))
        
        # count unique ports
        unique_ports = set(port for _, port in self._port_history[src_ip])
        
        if len(unique_ports) >= self.port_scan_threshold:
            # clear history to avoid repeated alerts
            self._port_history[src_ip] = []
            
            return {
                "severity": "high",
                "rule_name": "port_scan_detection",
                "description": f"Port scan detected: {len(unique_ports)} unique ports from {src_ip}",
                "source_ip": src_ip,
                "destination_ip": None,
            }
        
        return None
    
    def check_all(self, connection: Dict[str, Any], known_macs: List[str] = None) -> List[Dict[str, Any]]:
        """
        Run all detection rules on a connection
        
        Returns list of triggered alerts (can be empty).
        """
        alerts = []
        
        # check suspicious port
        alert = self.check_suspicious_port(connection)
        if alert:
            alerts.append(alert)
        
        # check port scan
        alert = self.check_port_scan(connection)
        if alert:
            alerts.append(alert)
        
        return alerts