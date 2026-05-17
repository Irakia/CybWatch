"""
Alerts API Router
"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from ..database import Database, get_db

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def severity_color(severity: str) -> str:
    """get color class for severity"""
    colors = {
        "critical": "text-red-500",
        "high": "text-orange-400",
        "medium": "text-yellow-400",
        "low": "text-blue-400",
    }
    return colors.get(severity, "text-gray-400")


def severity_bg(severity: str) -> str:
    """get background class for severity"""
    colors = {
        "critical": "bg-red-500/20",
        "high": "bg-orange-400/20",
        "medium": "bg-yellow-400/20",
        "low": "bg-blue-400/20",
    }
    return colors.get(severity, "bg-gray-400/20")


@router.get("/recent", response_class=HTMLResponse)
async def get_recent_alerts(db: Database = Depends(get_db)):
    """get recent alerts for dash"""
    alerts = await db.get_alerts(limit=5)
    
    if not alerts:
        return '<p class="text-gray-400">No alerts</p>'
    
    html = '<ul class="space-y-2">'
    for a in alerts:
        color = severity_color(a.get("severity", ""))
        bg = severity_bg(a.get("severity", ""))
        ack = "✓" if a.get("acknowledged") else ""
        html += f'''
        <li class="flex justify-between items-center py-2 border-b border-gray-700">
            <div>
                <span class="{color} {bg} px-2 py-1 rounded text-xs font-semibold uppercase mr-2">
                    {a.get("severity", "?")}
                </span>
                <span>{a.get("description", "No description")}</span>
            </div>
            <span class="text-green-400">{ack}</span>
        </li>
        '''
    html += '</ul>'
    return html


@router.get("/list", response_class=HTMLResponse)
async def get_alerts_list(db: Database = Depends(get_db)):
    """get alerts as table rows"""
    alerts = await db.get_alerts()
    
    if not alerts:
        return '<tr><td colspan="7" class="px-6 py-4 text-gray-400">No alerts</td></tr>'
    
    html = ""
    for a in alerts:
        color = severity_color(a.get("severity", ""))
        bg = severity_bg(a.get("severity", ""))
        status_color = "text-green-400" if a.get("acknowledged") else "text-yellow-400"
        status_text = "Acknowledged" if a.get("acknowledged") else "Open"

        if a.get("acknowledged"):
            ack_button = ""
        else:
            alert_id = a.get("id")
            ack_button = (
                f'<button onclick="acknowledgeAlert({alert_id})" '
                f'class="text-cyan-400 hover:text-cyan-300 text-sm">'
                f'Acknowledge</button>'
            )

        html += f'''
        <tr class="border-b border-gray-700 hover:bg-gray-750">
            <td class="px-6 py-4">
                <span class="{color} {bg} px-2 py-1 rounded text-xs font-semibold uppercase">
                    {a.get("severity", "?")}
                </span>
            </td>
            <td class="px-6 py-4">{a.get("rule_name", "-")}</td>
            <td class="px-6 py-4">{a.get("description", "-")}</td>
            <td class="px-6 py-4">{a.get("source_ip", "-")}</td>
            <td class="px-6 py-4 text-sm text-gray-400">{a.get("timestamp", "-")}</td>
            <td class="px-6 py-4"><span class="{status_color}">● {status_text}</span></td>
            <td class="px-6 py-4">{ack_button}</td>
        </tr>
        '''
    return html


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: Database = Depends(get_db)):
    """acknnowledge a single alert"""
    await db.acknowledge_alert(alert_id)
    return {"success": True}


@router.post("/acknowledge-all")
async def acknowledge_all(db: Database = Depends(get_db)):
    """acknowledge all alerts"""
    await db.acknowledge_all_alerts()
    return {"success": True}
