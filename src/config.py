"""
Cybwatch Configuration
loads settings from a .env
"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # application
    app_name: str = "Cybwatch"
    debug: bool = False
    
    # Database
    database_path: Path = Path("cybwatch.db")
    
    # Zeek Config
    zeek_log_dir: Path = Path("/opt/zeek/logs/current")
    
    # Nmap Config
    nmap_target_network: str = "10.0.0.0/24"
    
    # Detection thresholds
    port_scan_threshold: int = 10  # unique ports to trigger alert
    port_scan_window_seconds: int = 60
    high_traffic_threshold_mb: float = 100.0  # mb in 1 hour
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
