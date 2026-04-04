"""
Devices API Router
"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from ..database import Database, get_db

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/recent", response_class=HTMLResponse)
async def get_recent_devices(db: Database = Depends(get_db)):
    """get recent devices for dash"""
    devices = await db.get_devices(limit=5)
    
    if not devices:
        return '<p class="text-gray-400">No devices found</p>'
    
    html = '<ul class="space-y-2">'
    for d in devices:
        status = "🟢" if d.get("is_known") else "🟡"
        name = d.get("hostname") or d.get("ip_address") or "Unknown"
        vendor = d.get("vendor") or ""
        html += f'''
        <li class="flex justify-between items-center py-2 border-b border-gray-700">
            <div>
                <span class="mr-2">{status}</span>
                <span class="font-medium">{name}</span>
                <span class="text-gray-400 text-sm ml-2">{vendor}</span>
            </div>
            <span class="text-gray-400 text-sm">{d.get("ip_address", "")}</span>
        </li>
        '''
    html += '</ul>'
    return html


@router.get("/list", response_class=HTMLResponse)
async def get_devices_list(db: Database = Depends(get_db)):
    """get devices as table rows"""
    devices = await db.get_devices()
    
    if not devices:
        return '<tr><td colspan="7" class="px-6 py-4 text-gray-400">No devices found</td></tr>'
    
    html = ""
    for d in devices:
        status_color = "text-green-400" if d.get("is_known") else "text-yellow-400"
        status_text = "Known" if d.get("is_known") else "Unknown"
        html += f'''
        <tr class="border-b border-gray-700 hover:bg-gray-750">
            <td class="px-6 py-4"><span class="{status_color}">● {status_text}</span></td>
            <td class="px-6 py-4">{d.get("ip_address", "-")}</td>
            <td class="px-6 py-4 font-mono text-sm">{d.get("mac_address", "-")}</td>
            <td class="px-6 py-4">{d.get("hostname", "-")}</td>
            <td class="px-6 py-4">{d.get("vendor", "-")}</td>
            <td class="px-6 py-4 text-sm text-gray-400">{d.get("last_seen", "-")}</td>
            <td class="px-6 py-4">
                <button 
                    hx-post="/api/devices/{d.get("id")}/toggle"
                    hx-swap="none"
                    hx-trigger="click"
                    class="text-cyan-400 hover:text-cyan-300 text-sm">
                    {"Mark Unknown" if d.get("is_known") else "Mark Known"}
                </button>
            </td>
        </tr>
        '''
    return html


@router.post("/{device_id}/toggle")
async def toggle_device_known(device_id: int, db: Database = Depends(get_db)):
    """toggle device known"""
    devices = await db.get_devices()
    device = next((d for d in devices if d.get("id") == device_id), None)
    
    if device:
        new_status = not device.get("is_known", False)
        await db.mark_device_known(device_id, new_status)
    
    return {"success": True}
