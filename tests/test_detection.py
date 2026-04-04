"""Test for detection engine"""

from src.detection import DetectionEngine


class TestDetectionEngine:
    
    def test_suspicious_port_triggers(self):
        engine = DetectionEngine()
        connection = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 22}
        
        result = engine.check_suspicious_port(connection)
        
        assert result is not None
        assert result["severity"] == "high"
        assert "22" in result["description"]
    
    def test_normal_port_no_trigger(self):
        engine = DetectionEngine()
        connection = {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 443}
        
        result = engine.check_suspicious_port(connection)
        
        assert result is None
    
    def test_new_device_triggers(self):
        engine = DetectionEngine()
        known = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        
        result = engine.check_new_device("99:99:99:99:99:99", known)
        
        assert result is not None
        assert result["severity"] == "medium"
    
    def test_known_device_no_trigger(self):
        engine = DetectionEngine()
        known = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        
        result = engine.check_new_device("AA:BB:CC:DD:EE:FF", known)
        
        assert result is None
