from datetime import datetime

from config.settings import Config
from storage.database import LogEvent, Severity, ThreatType
from analyzers.threat_detector import ThreatDetector


def test_brute_force_detection(temp_db):
    detector = ThreatDetector(temp_db, Config())
    event = LogEvent(
        id=1,
        timestamp=datetime.now(),
        source="test",
        hostname="host-a",
        event_type="failed_login",
        event_id=4625,
        username="admin",
        source_ip="203.0.113.10",
        message="failed",
        raw_data="x",
        hash="hash-brute",
    )

    alert = None
    for _ in range(10):
        alert = detector.analyze_event(event)

    assert alert is not None
    assert alert.threat_type == ThreatType.BRUTE_FORCE
    assert alert.severity == Severity.HIGH


def test_suspicious_process_detection(temp_db):
    detector = ThreatDetector(temp_db, Config())
    event = LogEvent(
        id=2,
        timestamp=datetime.now(),
        source="test",
        hostname="host-b",
        event_type="process_created",
        event_id=4688,
        username="admin",
        source_ip=None,
        message="powershell.exe -enc SQBFAFg=",
        raw_data="y",
        hash="hash-proc",
    )
    alert = detector.analyze_event(event)
    assert alert is not None
    assert alert.threat_type == ThreatType.SUSPICIOUS_PROCESS
    assert alert.severity == Severity.CRITICAL


def test_detection_rules_catalog(temp_db):
    detector = ThreatDetector(temp_db, Config())
    assert len(detector.rules) == 6
    assert detector.rules[0].mitre_technique == "T1110"


def test_update_rule_metadata(temp_db):
    detector = ThreatDetector(temp_db, Config())
    updated = detector.update_rule_metadata(1, {"name": "Updated Rule", "severity": "CRITICAL"})
    assert updated["name"] == "Updated Rule"
    assert updated["severity"] == "CRITICAL"
