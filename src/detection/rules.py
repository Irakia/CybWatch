"""
Cybwatch Detection Engine

checks connections/devices for suspicious activity
"""

from typing import Optional, List, Dict, Any


SUSPICIOUS_PORTS = [22, 23, 135, 139, 445, 3389, 1433, 3306, 5432]


class DetectionEngine:
    """Detection rules"""
    
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
