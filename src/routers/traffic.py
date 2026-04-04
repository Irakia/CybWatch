"""
Traffic API Router
"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from ..database import Database, get_db

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("/list", response_class=HTMLResponse)
async def get_traffic_list(db: Database = Depends(get_db)):
    """get connections in tablerows"""
    connections = await db.get_connections(limit=50)
    
    if not connections:
        return '<tr><td colspan="7" class="px-6 py-4 text-gray-400">No connections recorded</td></tr>'
    
    html = ""
    for c in connections:
        # formatting
        bytes_total = (c.get("bytes_sent") or 0) + (c.get("bytes_received") or 0)
        if bytes_total > 1_000_000:
            bytes_str = f"{bytes_total / 1_000_000:.1f} MB"
        elif bytes_total > 1_000:
            bytes_str = f"{bytes_total / 1_000:.1f} KB"
        else:
            bytes_str = f"{bytes_total} B"
        

        duration = c.get("duration")
        if duration:
            duration_str = f"{duration:.2f}s"
        else:
            duration_str = "-"
        


        timestamp = c.get("timestamp", "-")
        if timestamp and timestamp != "-":
            timestamp = str(timestamp)[:19]
        
        html += f'''
        <tr class="border-b border-gray-700 hover:bg-gray-750">
            <td class="px-6 py-4 text-sm text-gray-400">{timestamp}</td>
            <td class="px-6 py-4 font-mono text-sm">{c.get("src_ip", "-")}:{c.get("src_port", "-")}</td>
            <td class="px-6 py-4 font-mono text-sm">{c.get("dst_ip", "-")}:{c.get("dst_port", "-")}</td>
            <td class="px-6 py-4">{c.get("protocol", "-").upper() if c.get("protocol") else "-"}</td>
            <td class="px-6 py-4">{c.get("service", "-") or "-"}</td>
            <td class="px-6 py-4">{duration_str}</td>
            <td class="px-6 py-4">{bytes_str}</td>
        </tr>
        '''
    return html
