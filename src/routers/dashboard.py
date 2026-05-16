"""
Dashboard API Router

"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from ..database import Database, get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_class=HTMLResponse)
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


@router.get("/chart/connections")
async def get_connections_chart_data(db: Database = Depends(get_db)):
    """Get connection data for chart (last 24 hours by hour)."""
    data = await db.get_connections_by_hour(hours=24)
    
    # Format for Chart.js
    labels = []
    values = []
    for row in data:
        hour = row.get("hour", "")
        if hour:
            # Extract just the hour part for display
            labels.append(hour[11:16] if len(hour) > 11 else hour)
        values.append(row.get("count", 0))
    
    return JSONResponse({
        "labels": labels,
        "values": values
    })


@router.get("/chart/alerts")
async def get_alerts_chart_data(db: Database = Depends(get_db)):
    """Get alert data grouped by rule for chart."""
    data = await db.get_alerts_by_rule()
    
    labels = [row.get("rule_name", "unknown") for row in data]
    values = [row.get("count", 0) for row in data]
    
    return JSONResponse({
        "labels": labels,
        "values": values
    })
