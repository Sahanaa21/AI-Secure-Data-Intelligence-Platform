import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.modules.log_analyzer import analyze_log
from backend.modules.risk_engine import calculate_risk

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "AI Secure Data Intelligence Platform"}

def test_password_detection():
    # Test that plain-text passwords are flagged as critical
    sample_log = "2026-03-27 INFO email=test@example.com password=secretpass123 login success"
    result = analyze_log(sample_log)
    findings = result["findings"]
    
    password_findings = [f for f in findings if f["type"] == "password"]
    assert len(password_findings) > 0
    assert password_findings[0]["risk"] == "critical"

def test_apikey_detection():
    # Test that stripe/generic API keys are detected
    sample_log = "DEBUG Using API key sk_live_51MabcXYZ123 for payment processing"
    result = analyze_log(sample_log)
    findings = result["findings"]
    
    key_findings = [f for f in findings if f["type"] in ("api_key", "generic_secret_key", "stripe_key")]
    assert len(key_findings) > 0

def test_brute_force_detection():
    # 4 consecutive failed authentications should flag brute force
    sample_log = """
    WARN Auth failed for user
    WARN Auth failed for user
    WARN Auth failed for user
    WARN Auth failed for user
    """
    result = analyze_log(sample_log)
    findings = result["findings"]
    brute_force = [f for f in findings if f["type"] == "brute_force_attempt"]
    assert len(brute_force) > 0
    assert brute_force[0]["risk"] == "critical"

def test_risk_scoring():
    # Mix of low and critical risks
    findings = [
        {"type": "password", "risk": "critical", "score": 10},
        {"type": "email", "risk": "low", "score": 2},
        {"type": "ip_address", "risk": "low", "score": 1}
    ]
    score, level = calculate_risk(findings)
    assert score >= 10  # Because critical alone is 10
    assert level == "critical"

def test_safe_log():
    # Normal operations should have no risks
    sample_log = "INFO User loaded settings panel successfully via GET /api/v1/settings"
    result = analyze_log(sample_log)
    findings = result["findings"]
    score, level = calculate_risk(findings)
    assert len(findings) == 0
    assert level == "safe"
