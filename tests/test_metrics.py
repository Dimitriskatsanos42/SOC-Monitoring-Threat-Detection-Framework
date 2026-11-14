from metrics import SOC_COLLECTOR_UP, SOC_EVENTS_PROCESSED_TOTAL, SOC_HTTP_REQUESTS_TOTAL


def test_metrics_endpoint_exposes_prometheus_data(app_client):
    client, _, _ = app_client

    client.get("/api/health")
    response = client.get("/metrics")

    assert response.status_code == 200
    text = response.text
    assert "soc_http_requests_total" in text
    assert "soc_events_processed_total" in text
    assert "soc_collector_up" in text


def test_metrics_are_updated_on_requests(app_client):
    client, _, _ = app_client

    before = SOC_HTTP_REQUESTS_TOTAL.labels(method="GET", route="/api/health", status_code="200")._value.get()
    client.get("/api/health")
    after = SOC_HTTP_REQUESTS_TOTAL.labels(method="GET", route="/api/health", status_code="200")._value.get()

    assert after >= before + 1

    SOC_EVENTS_PROCESSED_TOTAL.labels(source="linux", event_type="failed_login").inc()
    SOC_COLLECTOR_UP.labels(collector="Linux Syslog").set(1)
