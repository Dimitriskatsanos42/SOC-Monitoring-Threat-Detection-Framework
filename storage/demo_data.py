"""Demo telemetry seeding for presentations and empty environments."""

from datetime import datetime, timedelta
import random

from storage.database import Database, LogEvent, ThreatAlert, Severity, ThreatType


DEMO_HOSTS = ["DC-01", "WEB-SRV-02", "WORKSTATION-14", "VPN-GW-01"]
DEMO_IPS = ["203.0.113.44", "198.51.100.17", "192.0.2.88", "10.20.30.41"]
DEMO_USERS = ["admin", "svc_backup", "jdoe", "guest", "root"]


def seed_demo_data(db: Database, hostname: str = "SOC-DEMO") -> dict:
    """Populate the database with realistic SOC demo telemetry."""
    now = datetime.now()
    events_created = 0
    alerts_created = 0

    event_templates = [
        ("failed_login", 4625, "Authentication failed for user '{user}' from {ip}"),
        ("failed_login", 4625, "Multiple invalid logon attempts detected for '{user}'"),
        ("successful_login", 4624, "Successful logon for '{user}' from {ip}"),
        ("process_created", 4688, "Process created: powershell.exe -enc SQBFAFg..."),
        ("sudo_failure", None, "sudo: {user} : user NOT in sudoers"),
        ("invalid_user", None, "Invalid user '{user}' attempted login from {ip}"),
        ("audit_log_cleared", 1102, "Audit log was cleared by subject {user}"),
    ]

    for index in range(48):
        template = event_templates[index % len(event_templates)]
        event_type, event_id, message = template
        user = random.choice(DEMO_USERS)
        ip = random.choice(DEMO_IPS)
        host = random.choice(DEMO_HOSTS)
        ts = now - timedelta(minutes=index * 17)
        msg = message.format(user=user, ip=ip)
        raw = f"{ts.isoformat()}|{event_type}|{msg}"

        event = LogEvent(
            id=None,
            timestamp=ts,
            source="demo",
            hostname=host,
            event_type=event_type,
            event_id=event_id,
            username=user,
            source_ip=ip if "ip" in message else None,
            message=msg,
            raw_data=raw,
            hash=LogEvent.compute_hash(raw),
        )
        if db.insert_event(event):
            events_created += 1

    alert_templates = [
        (ThreatType.BRUTE_FORCE, Severity.HIGH, "T1110", "Brute force attack from 203.0.113.44 (12 attempts / 60s)"),
        (ThreatType.FAILED_LOGIN, Severity.MEDIUM, "T1078", "Repeated failed logins for user 'admin'"),
        (ThreatType.SUSPICIOUS_PROCESS, Severity.CRITICAL, "T1059.001", "Suspicious PowerShell encoded command on WEB-SRV-02"),
        (ThreatType.PRIVILEGE_ESCALATION, Severity.MEDIUM, "T1548", "Failed sudo escalation by guest on WORKSTATION-14"),
        (ThreatType.PORT_SCAN, Severity.MEDIUM, "T1046", "Potential port scan from 198.51.100.17"),
        (ThreatType.ANOMALY, Severity.CRITICAL, "T1070.001", "Audit log cleared on DC-01"),
    ]

    analysts = ["Analyst A. Papadopoulos", "Analyst M. Ioannou", "Unassigned"]
    for index, (threat_type, severity, mitre, description) in enumerate(alert_templates):
        alert = ThreatAlert(
            id=None,
            timestamp=now - timedelta(hours=index + 1),
            threat_type=threat_type,
            severity=severity,
            source_ip=DEMO_IPS[index % len(DEMO_IPS)],
            target_user=DEMO_USERS[index % len(DEMO_USERS)],
            hostname=DEMO_HOSTS[index % len(DEMO_HOSTS)],
            description=description,
            event_count=random.randint(3, 18),
            acknowledged=index > 2,
            related_event_ids=[],
        )
        alert_id = db.insert_alert(alert)
        if alert_id:
            alerts_created += 1
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE threat_alerts SET mitre_technique = ?, assigned_analyst = ? WHERE id = ?",
                    (mitre, analysts[index % len(analysts)], alert_id),
                )
                conn.commit()

    return {
        "hostname": hostname,
        "events_created": events_created,
        "alerts_created": alerts_created,
        "message": "Demo telemetry loaded successfully",
    }
