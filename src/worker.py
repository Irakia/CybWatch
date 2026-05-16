"""
Cybwatch Background Worker

Continuously runs functions for cybwatch
"""

import asyncio
import signal
import sys
import time
from pathlib import Path
from datetime import datetime

from .config import settings
from .database import db
from .parsers import ZeekParser, NmapParser
from .detection import DetectionEngine
from .alerts import EmailNotifier
from .threat_intel import BlocklistChecker


class Worker:
    """Background monitoring worker"""
    
    def __init__(self):
        self.parser = ZeekParser(log_dir=settings.zeek_log_dir)
        self.nmap_parser = NmapParser()
        self.detector = DetectionEngine(
            port_scan_threshold=settings.port_scan_threshold,
            port_scan_window=settings.port_scan_window_seconds,
        )
        self.notifier = EmailNotifier()
        self.blocklist = BlocklistChecker(blocklist_dir=Path("data/blocklists"))
        self.running = False
        self._last_position = 0
        self._conn_log_path = settings.zeek_log_dir / "conn.log"
        self._last_nmap_scan = 0  # Timestamp of last scan
    
    async def start(self):
        """Start the monitoring loop"""
        print(f"[Worker] Starting Cybwatch worker...")
        print(f"[Worker] Monitoring: {self._conn_log_path}")
        print(f"[Worker] Email enabled: {settings.email_enabled}")
        print(f"[Worker] Nmap enabled: {settings.nmap_scan_enabled}")
        print(f"[Worker] Nmap interval: {settings.nmap_scan_interval_minutes} minutes")
        
        # Load threat intel blocklists
        blocklist_count = self.blocklist.load_blocklists()
        print(f"[Worker] Threat intel: {blocklist_count} blocklist entries loaded")
        
        await db.connect()
        self.running = True
        
        # Start at end of file (don't process old entries)
        if self._conn_log_path.exists():
            self._last_position = self._conn_log_path.stat().st_size
        
        try:
            while self.running:
                await self._process_logs()
                await self._maybe_run_nmap()
                await asyncio.sleep(10)
        finally:
            await db.disconnect()
            print("[Worker] Stopped.")
    
    def stop(self):
        """Stop the monitoring loop."""
        print("[Worker] Stopping...")
        self.running = False
    
    async def _process_logs(self):
        """Read new log entries and process them"""
        if not self._conn_log_path.exists():
            return
        
        current_size = self._conn_log_path.stat().st_size
        
        # file was rotated
        if current_size < self._last_position:
            self._last_position = 0
        
        # no new data
        if current_size == self._last_position:
            return
        
        # read new lines
        connections = []
        try:
            with open(self._conn_log_path, "r") as f:
                f.seek(self._last_position)
                fields = None
                
                for line in f:
                    if line.startswith("#fields"):
                        fields = line.strip().split("\t")[1:]
                        continue
                    elif line.startswith("#"):
                        continue
                    
                    if fields is None:
                        fields = self.parser.CONN_LOG_FIELDS
                    
                    record = self.parser.parse_line(line, fields)
                    if record:
                        normalized = self.parser.parse_conn_record(record)
                        if normalized.get("timestamp"):
                            connections.append(normalized)
                
                self._last_position = f.tell()
        
        except Exception as e:
            print(f"[Worker] Error reading log: {e}")
            return
        
        if not connections:
            return
        
        print(f"[Worker] Processing {len(connections)} new connections...")
        
        # Insert connections into database
        await db.insert_connections_batch(connections)
        
        # Get enabled rules
        enabled_rules = await db.get_detection_rules(enabled_only=True)
        enabled_rule_names = {r["name"] for r in enabled_rules}
        
        # Run detection on each connection
        for conn in connections:
            alerts = self.detector.check_all(conn)
            
            for alert in alerts:
                # Only process if rule is enabled
                if alert["rule_name"] in enabled_rule_names:
                    await self._handle_alert(alert)
            
            # Check threat intel blocklist
            if "malicious_ip_connection" in enabled_rule_names:
                threat = self.blocklist.check_connection(conn)
                if threat:
                    alert = {
                        "severity": "critical",
                        "rule_name": "malicious_ip_connection",
                        "description": f"Connection to known malicious IP: {threat['ip']} ({threat['threat_type']})",
                        "source_ip": conn.get("src_ip"),
                        "destination_ip": conn.get("dst_ip"),
                    }
                    await self._handle_alert(alert)
    
    async def _maybe_run_nmap(self):
        """Run Nmap scan if enough time has passed."""
        if not settings.nmap_scan_enabled:
            return
        
        now = time.time()
        interval_seconds = settings.nmap_scan_interval_minutes * 60
        
        if now - self._last_nmap_scan < interval_seconds:
            return
        
        print(f"[Worker] Running Nmap scan on {settings.nmap_target_network}...")
        self._last_nmap_scan = now
        
        try:
            start_time = time.time()
            hosts = await asyncio.to_thread(
                self.nmap_parser.scan_network,
                settings.nmap_target_network
            )
            duration = time.time() - start_time
            
            print(f"[Worker] Nmap found {len(hosts)} hosts in {duration:.1f}s")
            
            # Record scan
            await db.record_scan(
                scan_type="discovery",
                targets=settings.nmap_target_network,
                duration_seconds=duration,
                hosts_found=len(hosts),
                results_summary=f"Found {len(hosts)} hosts"
            )
            
            # Get known MACs for new device detection
            devices = await db.get_devices()
            known_macs = [d["mac_address"] for d in devices if d.get("is_known")]
            
            # Get enabled rules
            enabled_rules = await db.get_detection_rules(enabled_only=True)
            enabled_rule_names = {r["name"] for r in enabled_rules}
            
            # Process discovered hosts
            for host in hosts:
                mac = host.get("mac")
                if mac:
                    await db.upsert_device(
                        mac_address=mac,
                        ip_address=host.get("ip"),
                        hostname=host.get("hostname"),
                        vendor=host.get("vendor")
                    )
                    
                    # Check for new device alert (only if rule is enabled)
                    if "new_device_alert" in enabled_rule_names:
                        alert = self.detector.check_new_device(mac, known_macs)
                        if alert:
                            alert["source_ip"] = host.get("ip")
                            await self._handle_alert(alert)
        
        except Exception as e:
            print(f"[Worker] Nmap scan error: {e}")
    
    async def _handle_alert(self, alert: dict):
        """Save alert to database and send notification"""
        print(f"[Worker] ALERT: {alert['rule_name']} - {alert['description']}")
        
        # save to database
        await db.create_alert(
            severity=alert["severity"],
            rule_name=alert["rule_name"],
            description=alert["description"],
            source_ip=alert.get("source_ip"),
            destination_ip=alert.get("destination_ip"),
        )
        
        # send email
        if settings.email_enabled:
            sent = self.notifier.send(alert)
            if sent:
                print(f"[Worker] Email sent for: {alert['rule_name']}")
            else:
                print(f"[Worker] Email failed for: {alert['rule_name']}")


async def main():
    """Main entry point"""
    worker = Worker()
    
    # handle shutdown signals
    def shutdown(signum, frame):
        worker.stop()
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
