"""
Settings API Router
"""

import os
from pathlib import Path
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from ..database import Database, get_db
from ..config import settings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/email", response_class=HTMLResponse)
async def get_email_settings():
    """get email cconfig"""
    if settings.email_enabled:
        status_color = "text-green-400"
        status_text = "Enabled"
    else:
        status_color = "text-yellow-400"
        status_text = "Disabled"
    
    # psswd masking
    password_display = "••••••••" if settings.smtp_password else "Not set"
    
    return f'''
    <div class="space-y-3">
        <div class="flex justify-between">
            <span class="text-gray-400">Status</span>
            <span class="{status_color}">● {status_text}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">SMTP Host</span>
            <span>{settings.smtp_host or "Not set"}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">SMTP Port</span>
            <span>{settings.smtp_port}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">From</span>
            <span>{settings.email_from or "Not set"}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">To</span>
            <span>{settings.email_to or "Not set"}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Password</span>
            <span>{password_display}</span>
        </div>
    </div>
    '''


@router.get("/rules", response_class=HTMLResponse)
async def get_rules_settings(db: Database = Depends(get_db)):
    """get detection rules"""
    rules = await db.get_detection_rules()
    
    if not rules:
        return '<p class="text-gray-400">No rules configured</p>'
    
    html = '<div class="space-y-3">'
    for r in rules:
        enabled = r.get("enabled")
        status_color = "text-green-400" if enabled else "text-gray-400"
        status_text = "Active" if enabled else "Disabled"
        severity = r.get("severity", "medium").upper()
        rule_id = r.get("id")
        
        # Toggle button
        if enabled:
            btn_class = "bg-green-600 hover:bg-green-700"
            btn_text = "Enabled"
        else:
            btn_class = "bg-gray-600 hover:bg-gray-500"
            btn_text = "Disabled"
        
        html += f'''
        <div class="flex justify-between items-center py-2 border-b border-gray-700">
            <div>
                <span class="font-medium">{r.get("name", "Unknown")}</span>
                <span class="text-gray-400 text-sm ml-2">({severity})</span>
            </div>
            <button hx-post="/api/settings/rules/{rule_id}/toggle"
                    hx-target="#rules-container"
                    hx-swap="innerHTML"
                    class="{btn_class} px-3 py-1 rounded text-sm">
                {btn_text}
            </button>
        </div>
        '''
    html += '</div>'
    return html


@router.post("/rules/{rule_id}/toggle", response_class=HTMLResponse)
async def toggle_rule(rule_id: int, db: Database = Depends(get_db)):
    """Toggle a detection rule on/off."""
    await db.toggle_rule(rule_id)
    # Return updated rules list
    return await get_rules_settings(db)


@router.get("/system", response_class=HTMLResponse)
async def get_system_info():
    """get system info"""

    db_path = settings.database_path
    if db_path.exists():
        db_size = db_path.stat().st_size
        if db_size > 1_000_000:
            db_size_str = f"{db_size / 1_000_000:.1f} MB"
        else:
            db_size_str = f"{db_size / 1_000:.1f} KB"
    else:
        db_size_str = "Not created"
    
    return f'''
    <div class="space-y-3">
        <div class="flex justify-between">
            <span class="text-gray-400">Database Path</span>
            <span class="font-mono text-sm">{settings.database_path}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Database Size</span>
            <span>{db_size_str}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Target Network</span>
            <span class="font-mono">{settings.nmap_target_network}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Debug Mode</span>
            <span>{"Enabled" if settings.debug else "Disabled"}</span>
        </div>
    </div>
    '''


@router.get("/zeek", response_class=HTMLResponse)
async def get_zeek_status():
    """get zeek status"""
    log_dir = settings.zeek_log_dir
    conn_log = log_dir / "conn.log"
    
    if conn_log.exists():
        status_color = "text-green-400"
        status_text = "Logs Available"
        log_size = conn_log.stat().st_size
        if log_size > 1_000_000:
            log_size_str = f"{log_size / 1_000_000:.1f} MB"
        else:
            log_size_str = f"{log_size / 1_000:.1f} KB"
    else:
        status_color = "text-yellow-400"
        status_text = "No Logs Found"
        log_size_str = "-"
    
    return f'''
    <div class="space-y-3">
        <div class="flex justify-between">
            <span class="text-gray-400">Status</span>
            <span class="{status_color}">● {status_text}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Log Directory</span>
            <span class="font-mono text-sm">{settings.zeek_log_dir}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">conn.log Size</span>
            <span>{log_size_str}</span>
        </div>
    </div>
    '''
