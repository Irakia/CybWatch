"""
Nmap XML Parser

Parses nmap XML output to extract devices
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional


class NmapParser:
    """Parser for Nmap XML output."""
    
    def parse_xml_file(self, filepath: Path) -> Dict[str, Any]:
        """Parse Nmap XML file."""
        if not filepath.exists():
            return {"hosts": []}
        
        tree = ET.parse(filepath)
        return self._parse_root(tree.getroot())
    
    def parse_xml_string(self, xml_string: str) -> Dict[str, Any]:
        """Parse Nmap XML string."""
        root = ET.fromstring(xml_string)
        return self._parse_root(root)
    
    def _parse_root(self, root: ET.Element) -> Dict[str, Any]:
        """Parse XML root element."""
        hosts = []
        for host in root.findall("host"):
            host_data = self._parse_host(host)
            if host_data:
                hosts.append(host_data)
        return {"hosts": hosts}
    
    def _parse_host(self, host: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse a single host element."""
        status = host.find("status")
        if status is None or status.get("state") != "up":
            return None
        
        host_data = {
            "ip_address": None,
            "mac_address": None,
            "vendor": None,
            "hostname": None,
        }
        
        # Get addresses
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                host_data["ip_address"] = addr.get("addr")
            elif addr_type == "mac":
                host_data["mac_address"] = addr.get("addr")
                host_data["vendor"] = addr.get("vendor")
        
        # Get hostname
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                host_data["hostname"] = hostname_elem.get("name")
        
        return host_data
    
    def get_devices_from_scan(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract device records for database insertion."""
        devices = []
        for host in scan_result.get("hosts", []):
            mac = host.get("mac_address")
            if not mac:
                continue
            devices.append({
                "mac_address": mac.upper(),
                "ip_address": host.get("ip_address"),
                "hostname": host.get("hostname"),
                "vendor": host.get("vendor"),
            })
        return devices