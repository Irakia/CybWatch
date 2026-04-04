"""Cybwatch API Routers"""

from .dashboard import router as dashboard_router
from .devices import router as devices_router
from .alerts import router as alerts_router
from .traffic import router as traffic_router
from .settings import router as settings_router

__all__ = [
    "dashboard_router",
    "devices_router", 
    "alerts_router",
    "traffic_router",
    "settings_router",
]
