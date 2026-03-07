"""
Cybwatch Pydantic Models

data models for validation/serialization
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Device(BaseModel):
    """Network device"""
    id: Optional[int] = None
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_known: bool = False
    notes: Optional[str] = None


class Connection(BaseModel):
    """Network connection from Zeek."""
    id: Optional[int] = None
    uid: Optional[str] = None  # Zeek unique ID
    timestamp: datetime
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # tcp, udp, icmp
    duration: Optional[float] = None  # seconds
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    conn_state: Optional[str] = None  # Zeek connection state
    service: Optional[str] = None  # service (http, ssh, etc)


class Alert(BaseModel):
    """Security alert.."""
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    rule_name: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None


class DetectionRule(BaseModel):
    """Detection rule configeration."""
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    enabled: bool = True
    severity: str = "medium"
    rule_type: str  # port_scan, port_match, threshold, new_device
    config: Optional[str] = None


class Scan(BaseModel):
    """Nmap scan record."""
    id: Optional[int] = None
    timestamp: Optional[datetime] = None
    scan_type: str  # quick, full, etc
    targets: str  
    duration_seconds: Optional[float] = None
    hosts_found: Optional[int] = None
    results_summary: Optional[str] = None
