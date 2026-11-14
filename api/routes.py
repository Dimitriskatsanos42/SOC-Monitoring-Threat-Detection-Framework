from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import platform
import socket
import time

from metrics import (
    CONTENT_TYPE_LATEST,
    generate_latest,
    SOC_HTTP_REQUESTS_TOTAL,
    SOC_HTTP_REQUEST_DURATION_SECONDS,
)

app = FastAPI(
    title="SOC Monitor API",
    description="Security Operations Center Monitoring Dashboard",
    version="1.0.0"
)

# Static assets for the dashboard UI
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start
    route = request.scope.get("route")
    route_name = getattr(route, "path", request.url.path)
    SOC_HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        route=route_name,
        status_code=str(response.status_code),
    ).inc()
    SOC_HTTP_REQUEST_DURATION_SECONDS.labels(
        method=request.method,
        route=route_name,
    ).observe(duration)
    return response

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


@app.get("/metrics")
async def metrics():
    """Expose Prometheus metrics for the SOC application."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _severity_label(value: int) -> str:
    return {
        4: "Critical",
        3: "High",
        2: "Medium",
        1: "Low",
    }.get(value, "Informational")


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(alert)
    normalized["severity_name"] = _severity_label(alert.get("severity"))
    normalized["mitre_technique"] = alert.get("mitre_technique") or "Tactic not mapped"
    normalized["assigned_analyst"] = alert.get("assigned_analyst") or "Unassigned"
    return normalized


@app.get("/api/stats")
async def get_statistics(days: int = Query(7, ge=1, le=90)):
    """Get aggregated statistics."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    stats = db.get_statistics(days=days)
    
    open_incidents = 0
    if db:
        open_incidents = len(db.get_alerts(unacknowledged_only=True, limit=1000))

    connected_agents = 0
    healthy_agents = 0
    offline_agents = 0
    if system_state.get("collector_channels"):
        connected_agents = len(system_state.get("collector_channels", [])) if system_state.get("collector_active") else 0
        healthy_agents = connected_agents
        offline_agents = 0 if system_state.get("collector_active") else len(system_state.get("collector_channels", []))

    detection_rules = len(detector.rules) if detector and hasattr(detector, "rules") else 0

    return {
        "success": True,
        "data": {
            **stats,
            "open_incidents": open_incidents,
            "detection_rules": detection_rules,
            "connected_agents": connected_agents,
            "offline_agents": offline_agents,
            "healthy_agents": healthy_agents,
            "events_per_second": round((stats.get("total_events", 0) / max(days * 86400, 1)), 4)
        }
    }


@app.get("/api/detection-rules")
async def get_detection_rules():
    """Get active detection rule definitions."""
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    return {
        "success": True,
        "data": [
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.name,
                "threat_type": rule.threat_type.value,
                "description": rule.description_template,
                "mitre_technique": rule.mitre_technique or "—",
            }
            for rule in detector.rules
        ]
    }


@app.post("/api/detection-rules/{rule_id}")
async def update_detection_rule(rule_id: int, payload: Dict[str, Any]):
    """Update detection rule metadata (name, severity, description, mitre)."""
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    updated = detector.update_rule_metadata(rule_id, payload)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "data": updated}


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    page: int = Query(1, ge=1),
    severity: Optional[int] = Query(None),
    acknowledged: Optional[bool] = Query(None)
):
    """Get recent alerts with pagination and filters."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    filters = {}
    if severity is not None:
        filters['severity'] = severity
    if acknowledged is not None:
        filters['acknowledged'] = acknowledged

    offset = (page - 1) * limit
    total = db.count_alerts(filters=filters)
    alerts = db.get_alerts(limit=limit, offset=offset, filters=filters)

    # Normalize alerts
    normalized = [_normalize_alert(a) for a in alerts]

    return {
        "success": True,
        "pagination": {"page": page, "per_page": limit, "total": total},
        "count": len(normalized),
        "data": normalized
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


@app.post("/api/demo/seed")
async def seed_demo():
    """Load realistic demo telemetry for presentations."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    from storage.demo_data import seed_demo_data
    result = seed_demo_data(db, hostname=socket.gethostname())
    return {"success": True, "data": result}

