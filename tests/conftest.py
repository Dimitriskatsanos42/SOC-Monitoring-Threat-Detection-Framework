"""Pytest fixtures for SOC Monitor tests."""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from config.settings import Config, DatabaseConfig
from storage.database import Database
from analyzers.threat_detector import ThreatDetector
from alerts.notifier import AlertNotifier
from api import routes


@pytest.fixture()
def temp_db():
    with tempfile.TemporaryDirectory() as tmp:
        config = DatabaseConfig(sqlite_path=Path(tmp) / "test.db")
        db = Database(config)
        yield db


@pytest.fixture()
def app_client(temp_db):
    config = Config()
    config.database = temp_db.config
    detector = ThreatDetector(temp_db, config)
    notifier = AlertNotifier(config)

    routes.db = temp_db
    routes.detector = detector
    routes.notifier = notifier
    routes.system_state = {
        "started_at": None,
        "database_type": "sqlite",
        "collector_type": "Test Collector",
        "collector_active": True,
        "collector_channels": ["Security", "System"],
        "collector_errors": [],
        "poll_interval": 10,
        "batch_size": 100,
        "api_host": "127.0.0.1",
        "api_port": 8080,
    }

    with TestClient(routes.app) as client:
        yield client, temp_db, detector
