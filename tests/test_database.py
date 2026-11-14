from datetime import datetime

from storage.database import LogEvent, ThreatAlert, Severity, ThreatType
from storage.demo_data import seed_demo_data


def test_insert_event_and_dedup(temp_db):
    event = LogEvent(
        id=None,
        timestamp=datetime.now(),
        source="test",
        hostname="host-a",
        event_type="failed_login",
        event_id=4625,
        username="admin",
        source_ip="10.0.0.5",
        message="failed login",
        raw_data="unique-raw-1",
        hash=LogEvent.compute_hash("unique-raw-1"),
    )
    first = temp_db.insert_event(event)
    second = temp_db.insert_event(event)
    assert first is not None
    assert second is None


def test_insert_alert_and_acknowledge(temp_db):
    alert = ThreatAlert(
        id=None,
        timestamp=datetime.now(),
        threat_type=ThreatType.BRUTE_FORCE,
        severity=Severity.HIGH,
        source_ip="10.0.0.5",
        target_user="admin",
        hostname="host-a",
        description="Brute force detected",
        event_count=5,
    )
    alert_id = temp_db.insert_alert(alert)
    assert alert_id > 0

    alerts = temp_db.get_alerts(limit=10)
    assert len(alerts) == 1
    assert temp_db.acknowledge_alert(alert_id) is True
    assert temp_db.get_alerts(filters={"acknowledged": True}, limit=10)[0]["acknowledged"] == 1


def test_count_alerts_with_filters(temp_db):
    for severity in (Severity.LOW, Severity.CRITICAL):
        temp_db.insert_alert(ThreatAlert(
            id=None,
            timestamp=datetime.now(),
            threat_type=ThreatType.FAILED_LOGIN,
            severity=severity,
            source_ip=None,
            target_user="user",
            hostname="host",
            description="test",
            event_count=1,
        ))
    assert temp_db.count_alerts(filters={"severity": Severity.CRITICAL.value}) == 1


def test_seed_demo_data(temp_db):
    result = seed_demo_data(temp_db)
    assert result["events_created"] > 0
    assert result["alerts_created"] > 0
    stats = temp_db.get_statistics(days=7)
    assert stats["total_events"] >= result["events_created"]
