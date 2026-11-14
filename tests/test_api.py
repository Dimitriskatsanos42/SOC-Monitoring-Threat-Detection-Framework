def test_health_endpoint(app_client):
    client, _, _ = app_client
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["components"]["database"] is True


def test_dashboard_page(app_client):
    client, _, _ = app_client
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "SOC Monitor" in response.text
    assert "/static/dashboard.css" in response.text


def test_stats_endpoint(app_client):
    client, db, _ = app_client
    from storage.demo_data import seed_demo_data
    seed_demo_data(db)

    response = client.get("/api/stats?days=7")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total_events"] > 0
    assert "detection_rules" in data


def test_alerts_pagination(app_client):
    client, db, _ = app_client
    from storage.demo_data import seed_demo_data
    seed_demo_data(db)

    response = client.get("/api/alerts?limit=3&page=1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["pagination"]["total"] >= 3
    assert len(payload["data"]) <= 3
    assert "severity_name" in payload["data"][0]


def test_demo_seed_endpoint(app_client):
    client, db, _ = app_client
    response = client.post("/api/demo/seed")
    assert response.status_code == 200
    payload = response.json()["data"]
    assert payload["events_created"] > 0
    assert payload["alerts_created"] > 0


def test_detection_rules_endpoint(app_client):
    client, _, _ = app_client
    response = client.get("/api/detection-rules")
    assert response.status_code == 200
    rules = response.json()["data"]
    assert len(rules) == 6
    assert rules[0]["mitre_technique"] == "T1110"


def test_system_status_endpoint(app_client):
    client, db, _ = app_client
    from storage.demo_data import seed_demo_data
    seed_demo_data(db)

    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total_events"] > 0
    assert data["collector_type"] == "Test Collector"
