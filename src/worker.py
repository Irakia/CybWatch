"""
Cybwatch Background Worker

Continuously runs functions for cybwatch
"""

import asyncio
import signal
import sys
from pathlib import Path
from datetime import datetime

from .config import settings
from .database import db
from .parsers import ZeekParser
from .detection import DetectionEngine
from .alerts import EmailNotifier


class Worker:
    """Background monitoring worker"""
    
    def __init__(self):
        self.parser = ZeekParser(log_dir=settings.zeek_log_dir)
        self.detector = DetectionEngine(
            port_scan_threshold=settings.port_scan_threshold,
            port_scan_window=settings.port_scan_window_seconds,
        )
        self.notifier = EmailNotifier()
        self.running = False
        self._last_position = 0
        self._conn_log_path = settings.zeek_log_dir / "conn.log"
    
    async def start(self):
        """Start the monitoring loop"""
        print(f"[Worker] Starting Cybwatch worker...")
        print(f"[Worker] Monitoring: {self._conn_log_path}")
        print(f"[Worker] Email enabled: {settings.email_enabled}")
        
        await db.connect()
        self.running = True
        
        # Start at end of file (don't process old entries)
        if self._conn_log_path.exists():
            self._last_position = self._conn_log_path.stat().st_size
        
        try:
            while self.running:
                await self._process_logs()
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
        
        # Run detection on each connection
        for conn in connections:
            alerts = self.detector.check_all(conn)
            
            for alert in alerts:
                await self._handle_alert(alert)
    
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
