"""
tests/test_backend_api.py — Unit & Integration Tests for Backend REST & WebSocket API.

Tests all endpoints:
  - GET /api/health
  - GET /api/sensors
  - GET /api/alerts (filters, search, pagination)
  - GET /api/alerts/{alert_id} & PATCH /api/alerts/{alert_id}
  - GET /api/flows/{flow_id}
  - GET /api/analytics/summary & GET /api/analytics/trends
  - GET /api/models
  - GET /api/export (CSV & JSON)
  - WebSocket /ws/alerts
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from storage.db import init_db, save_alert, save_flow, close_db


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    init_db()
    # Seed a sample flow and alert
    flow_data = {
        "flow_id": "test-flow-001",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": 6,
        "packets_fwd": 10,
        "packets_bwd": 5,
        "bytes_fwd": 1500,
        "bytes_bwd": 700,
        "total_packets": 15,
        "total_bytes": 2200,
        "start_time": time.time() - 10,
        "end_time": time.time(),
        "duration": 10.0,
        "state": "expired",
    }
    save_flow(flow_data)

    alert_data = {
        "alert_id": "alert-test-api-01",
        "timestamp": time.time(),
        "flow_id": "test-flow-001",
        "threat_class": "ddos",
        "confidence": 0.85,
        "severity": "CRITICAL",
        "severity_score": 0.80,
        "evidence": {"packets_per_sec": 450.0, "syn_ack_ratio": 12.0},
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 80,
        "proto": 6,
        "model_version": "v1.0",
        "status": "NEW",
    }
    save_alert(alert_data)
    yield
    close_db()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client: TestClient):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert "uptime_seconds" in data
    assert data["db_connected"] is True


def test_sensors_endpoint(client: TestClient):
    resp = client.get("/api/sensors")
    assert resp.status_code == 200
    sensors = resp.json()
    assert isinstance(sensors, list)
    assert len(sensors) >= 1
    assert "name" in sensors[0]


def test_get_alerts_pagination_and_filter(client: TestClient):
    resp = client.get("/api/alerts?limit=10&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)
    assert len(data["alerts"]) >= 1

    # Filter by class
    resp_ddos = client.get("/api/alerts?class=ddos")
    assert resp_ddos.status_code == 200
    assert any(a["threat_class"] == "ddos" for a in resp_ddos.json()["alerts"])

    # Search query
    resp_q = client.get("/api/alerts?q=192.168.1.100")
    assert resp_q.status_code == 200
    assert len(resp_q.json()["alerts"]) >= 1


def test_get_alert_detail(client: TestClient):
    resp = client.get("/api/alerts/alert-test-api-01")
    assert resp.status_code == 200
    alert = resp.json()
    assert alert["alert_id"] == "alert-test-api-01"
    assert alert["threat_class"] == "ddos"
    assert alert["evidence"]["packets_per_sec"] == 450.0
    assert alert["flow"] is not None
    assert alert["flow"]["flow_id"] == "test-flow-001"

    # Non-existent alert
    resp_404 = client.get("/api/alerts/non-existent-alert-id")
    assert resp_404.status_code == 404


def test_patch_alert(client: TestClient):
    payload = {
        "status": "INVESTIGATING",
        "notes": "Verified SYN flood against internal web server",
        "label": "TRUE_POSITIVE",
        "analyst_user": "sec_analyst_01",
    }
    resp = client.patch("/api/alerts/alert-test-api-01", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INVESTIGATING"
    assert data["updated"] is True

    # Re-fetch alert detail to verify annotation
    detail_resp = client.get("/api/alerts/alert-test-api-01")
    detail = detail_resp.json()
    assert detail["status"] == "INVESTIGATING"
    assert len(detail["annotations"]) >= 1
    assert detail["annotations"][-1]["notes"] == "Verified SYN flood against internal web server"


def test_flow_detail(client: TestClient):
    resp = client.get("/api/flows/test-flow-001")
    assert resp.status_code == 200
    flow = resp.json()
    assert flow["flow_id"] == "test-flow-001"
    assert flow["src_ip"] == "192.168.1.100"
    assert flow["total_bytes"] == 2200

    resp_404 = client.get("/api/flows/non-existent-flow")
    assert resp_404.status_code == 404


def test_analytics_summary(client: TestClient):
    resp = client.get("/api/analytics/summary")
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["total_alerts"] >= 1
    assert "by_class" in summary
    assert "by_severity" in summary
    assert "top_sources" in summary
    assert "top_destinations" in summary


def test_analytics_trends(client: TestClient):
    resp = client.get("/api/analytics/trends?window_hours=1&bucket_seconds=60")
    assert resp.status_code == 200
    trends = resp.json()
    assert "buckets" in trends
    assert isinstance(trends["buckets"], list)


def test_models_endpoint(client: TestClient):
    resp = client.get("/api/models")
    assert resp.status_code == 200
    models = resp.json()
    assert isinstance(models, list)
    assert len(models) >= 6
    classes = {m["threat_class"] for m in models}
    assert "c2_beacon" in classes
    assert "ddos" in classes
    assert "encrypted_malware" in classes


def test_export_alerts_csv_and_json(client: TestClient):
    # CSV export
    resp_csv = client.get("/api/export?format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    assert "Alert ID,Timestamp,Threat Class" in resp_csv.text

    # JSON export
    resp_json = client.get("/api/export?format=json")
    assert resp_json.status_code == 200
    assert "application/json" in resp_json.headers["content-type"]
    json_data = resp_json.json()
    assert isinstance(json_data, list)


def test_websocket_alerts(client: TestClient):
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text("ping")
        data = ws.receive_text()
        assert data == "pong"


def test_static_dashboard_served(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "NTRO Threat Detection" in resp.text
