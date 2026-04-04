"""
Dashboard API Router

"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from ..database import Database, get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_stats(db: Database = Depends(get_db)):
    """Get dashboard stats"""
    devices = await db.get_devices()
    alerts = await db.get_alerts()
    connections = await db.get_connections()
    unacknowledged = [a for a in alerts if not a.get("acknowledged")]
    
    return f"""
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <p class="text-gray-400 text-sm">Devices</p>
        <p class="text-3xl font-bold text-cyan-400">{len(devices)}</p>
    </div>
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <p class="text-gray-400 text-sm">Total Alerts</p>
        <p class="text-3xl font-bold text-yellow-400">{len(alerts)}</p>
    </div>
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <p class="text-gray-400 text-sm">Unacknowledged</p>
        <p class="text-3xl font-bold text-red-400">{len(unacknowledged)}</p>
    </div>
    <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <p class="text-gray-400 text-sm">Connections</p>
        <p class="text-3xl font-bold text-green-400">{len(connections)}</p>
    </div>
    """
