"""
Threat Intel - Blocklist Checker

Checks IPs against local blocklist files.
"""

import ipaddress
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from datetime import datetime


class BlocklistChecker:
    """Checks IPs against local blocklists."""
    
    def __init__(self, blocklist_dir: Path = None):
        self.blocklist_dir = blocklist_dir or Path("data/blocklists")
        self._bad_ips: Set[str] = set()
        self._bad_networks: List[ipaddress.IPv4Network] = []
        self._loaded_at: Optional[datetime] = None
        self._sources: List[str] = []
    
    def load_blocklists(self) -> int:
        """
        Load all blocklist files from the blocklist directory.
        
        Returns count of entries loaded.
        """
        self._bad_ips = set()
        self._bad_networks = []
        self._sources = []
        count = 0
        
        if not self.blocklist_dir.exists():
            print(f"[BlocklistChecker] Directory not found: {self.blocklist_dir}")
            return 0
        
        for filepath in self.blocklist_dir.glob("*.txt"):
            entries = self._load_file(filepath)
            count += entries
            if entries > 0:
                self._sources.append(filepath.name)
        
        self._loaded_at = datetime.now()
        print(f"[BlocklistChecker] Loaded {count} entries from {len(self._sources)} files")
        return count
    
    def _load_file(self, filepath: Path) -> int:
        """Load a single blocklist file."""
        count = 0
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    
                    # Handle lines with comments at end
                    if ";" in line:
                        line = line.split(";")[0].strip()
                    if "#" in line:
                        line = line.split("#")[0].strip()
                    
                    if not line:
                        continue
                    
                    try:
                        if "/" in line:
                            # It's a network (CIDR notation)
                            network = ipaddress.IPv4Network(line, strict=False)
                            self._bad_networks.append(network)
                        else:
                            # It's a single IP
                            ipaddress.IPv4Address(line)  # Validate
                            self._bad_ips.add(line)
                        count += 1
                    except ValueError:
                        # Skip invalid entries
                        continue
        
        except Exception as e:
            print(f"[BlocklistChecker] Error loading {filepath}: {e}")
        
        return count
    
    def is_malicious(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check if an IP is in the blocklist.
        
        Returns threat info dict if malicious, None if clean.
        """
        if not ip:
            return None
        
        # Skip private IPs
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return None
        except ValueError:
            return None
        
        # Check exact IP match
        if ip in self._bad_ips:
            return {
                "ip": ip,
                "threat_type": "Known Malicious IP",
                "source": "local_blocklist",
                "confidence": "high"
            }
        
        # Check network ranges
        for network in self._bad_networks:
            if ip_obj in network:
                return {
                    "ip": ip,
                    "threat_type": "Malicious IP Range",
                    "source": "local_blocklist",
                    "network": str(network),
                    "confidence": "high"
                }
        
        return None
    
    def check_connection(self, connection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if a connection involves a malicious IP.
        
        Checks both source and destination IPs.
        """
        # Check destination (more common - outbound to bad IP)
        dst_ip = connection.get("dst_ip")
        result = self.is_malicious(dst_ip)
        if result:
            result["direction"] = "outbound"
            result["local_ip"] = connection.get("src_ip")
            return result
        
        # Check source (inbound from bad IP)
        src_ip = connection.get("src_ip")
        result = self.is_malicious(src_ip)
        if result:
            result["direction"] = "inbound"
            result["local_ip"] = connection.get("dst_ip")
            return result
        
        return None
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get blocklist statistics."""
        return {
            "total_ips": len(self._bad_ips),
            "total_networks": len(self._bad_networks),
            "sources": self._sources,
            "loaded_at": self._loaded_at.isoformat() if self._loaded_at else None
        }
