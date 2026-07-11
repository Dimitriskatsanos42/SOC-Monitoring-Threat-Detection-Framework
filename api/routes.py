from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import platform
import socket

app = FastAPI(
    title="SOC Monitor API",
    description="Security Operations Center Monitoring Dashboard",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global references (set by main.py)
db = None
detector = None
notifier = None
system_state: Dict[str, Any] = {}

_DASHBOARD_PATH = Path(__file__).parent / "dashboard.html"


class AlertAcknowledge(BaseModel):
    alert_id: int


class ThresholdUpdate(BaseModel):
    failed_login_threshold: Optional[int] = None
    brute_force_threshold: Optional[int] = None
    failed_login_window_seconds: Optional[int] = None
    brute_force_window_seconds: Optional[int] = None


@app.get("/")
async def root():
    return {"status": "running", "service": "SOC Monitor"}


@app.get("/api/stats")
async def get_statistics(days: int = Query(7, ge=1, le=90)):
    """Get aggregated statistics."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    stats = db.get_statistics(days=days)
    return {
        "success": True,
        "data": stats
    }


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    unacknowledged_only: bool = Query(False)
):
    """Get recent alerts."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    alerts = db.get_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    return {
        "success": True,
        "count": len(alerts),
        "data": alerts
    }


@app.post("/api/alerts/acknowledge")
async def acknowledge_alert(data: AlertAcknowledge):
    """Acknowledge an alert."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    success = db.acknowledge_alert(data.alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {"success": True, "message": f"Alert {data.alert_id} acknowledged"}


@app.get("/api/threats/summary")
async def get_threat_summary(hours: int = Query(24, ge=1, le=168)):
    """Get threat summary."""
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    summary = detector.get_threat_summary(hours=hours)
    return {
        "success": True,
        "data": summary
    }


@app.get("/api/events/recent")
async def get_recent_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = None
):
    """Get recent log events."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        if event_type:
            cursor.execute("""
                SELECT * FROM log_events 
                WHERE event_type = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (event_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM log_events 
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
        
        events = [dict(row) for row in cursor.fetchall()]
    
    return {
        "success": True,
        "count": len(events),
        "data": events
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "database": db is not None,
            "detector": detector is not None,
            "notifier": notifier is not None
        }
    }


@app.get("/api/system/status")
async def system_status():
    """Runtime system status for dashboard and monitoring."""
    started_at = system_state.get("started_at")
    uptime_seconds = 0
    if started_at:
        uptime_seconds = int((datetime.now() - started_at).total_seconds())

    total_events = 0
    total_alerts = 0
    if db:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as n FROM log_events")
            total_events = cursor.fetchone()["n"]
            cursor.execute("SELECT COUNT(*) as n FROM threat_alerts")
            total_alerts = cursor.fetchone()["n"]

    notifications = {"discord": False, "telegram": False, "email": False}
    if notifier:
        notifications = {
            "discord": notifier.config.discord_enabled,
            "telegram": notifier.config.telegram_enabled,
            "email": notifier.config.email_enabled,
        }

    return {
        "success": True,
        "data": {
            "platform": platform.system(),
            "hostname": socket.gethostname(),
            "started_at": started_at.isoformat() if started_at else None,
            "uptime_seconds": uptime_seconds,
            "database_type": system_state.get("database_type", "sqlite"),
            "collector_type": system_state.get("collector_type"),
            "collector_active": system_state.get("collector_active", False),
            "collector_channels": system_state.get("collector_channels", []),
            "collector_errors": system_state.get("collector_errors", []),
            "poll_interval": system_state.get("poll_interval"),
            "batch_size": system_state.get("batch_size"),
            "api_host": system_state.get("api_host"),
            "api_port": system_state.get("api_port"),
            "total_events": total_events,
            "total_alerts": total_alerts,
            "notifications": notifications,
        }
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard HTML."""
    return HTMLResponse(_DASHBOARD_PATH.read_text(encoding="utf-8"))

