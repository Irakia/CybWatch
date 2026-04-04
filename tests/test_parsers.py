"""Test for parsers"""

import pytest
from pathlib import Path
from datetime import datetime

from src.parsers import ZeekParser, NmapParser


class TestZeekParser:
    
    def test_parse_line_valid(self):
        parser = ZeekParser()
        fields = ["ts", "uid", "src", "dst"]
        line = "1234567890.123\tCtest123\t10.0.0.1\t8.8.8.8"
        
        result = parser.parse_line(line, fields)
        
        assert result["uid"] == "Ctest123"
        assert result["src"] == "10.0.0.1"
    
    def test_parse_line_skips_comments(self):
        parser = ZeekParser()
        result = parser.parse_line("#fields ts uid", ["ts", "uid"])
        assert result is None
    
    def test_parse_conn_record(self):
        parser = ZeekParser()
        raw = {
            "ts": "1609459200.0",
            "uid": "Ctest123",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": "12345",
            "id.resp_h": "8.8.8.8",
            "id.resp_p": "443",
            "proto": "tcp",
            "service": "ssl",
            "duration": "1.5",
            "orig_bytes": "1000",
            "resp_bytes": "5000",
            "conn_state": "SF",
        }
        
        result = parser.parse_conn_record(raw)
        
        assert result["src_ip"] == "10.0.0.1"
        assert result["src_port"] == 12345
        assert result["dst_port"] == 443


class TestNmapParser:
    
    def test_parse_xml_basic(self):
        parser = NmapParser()
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test"/>
            </host>
        </nmaprun>
        """
        
        result = parser.parse_xml_string(xml)
        
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip_address"] == "10.0.0.1"
        assert result["hosts"][0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    
    def test_get_devices_skips_no_mac(self):
        parser = NmapParser()
        scan = {
            "hosts": [
                {"ip_address": "10.0.0.1", "mac_address": "AA:BB:CC:DD:EE:FF"},
                {"ip_address": "10.0.0.2", "mac_address": None},
            ]
        }
        
        devices = parser.get_devices_from_scan(scan)
        
        assert len(devices) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
