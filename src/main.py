"""
Cybwatch Network Security Monitor

fastapi application
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from .database import db
from .routers import (
    dashboard_router,
    devices_router,
    alerts_router,
    traffic_router,
    settings_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown"""
    await db.connect()
    yield
    await db.disconnect()


app = FastAPI(
    title="Cybwatch",
    description="Raspberry Pi Network Security Monitor",
    version="0.7.0",
    lifespan=lifespan,
)

# paths
BASE_DIR = Path(__file__).parent.parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


app.include_router(dashboard_router)
app.include_router(devices_router)
app.include_router(alerts_router)
app.include_router(traffic_router)
app.include_router(settings_router)

# web pages
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page."""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_page": "dashboard"
    })

@app.get("/devices", response_class=HTMLResponse)
async def devices(request: Request):
    """Devices page."""
    return templates.TemplateResponse("devices.html", {
        "request": request,
        "active_page": "devices"
    })


@app.get("/alerts", response_class=HTMLResponse)
async def alerts(request: Request):
    """Alerts page."""
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "active_page": "alerts"
    })


@app.get("/traffic", response_class=HTMLResponse)
async def traffic(request: Request):
    """Traffic page."""
    return templates.TemplateResponse("traffic.html", {
        "request": request,
        "active_page": "traffic"
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "active_page": "settings"
    })


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "ok"}
