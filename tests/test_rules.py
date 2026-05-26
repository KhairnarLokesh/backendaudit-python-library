import pytest
from pathlib import Path
from backend_audit.scanner import run_scan

def test_flask_app_audit():
    sample_dir = Path(__file__).parent / "sample_apps"
    flask_file = sample_dir / "flask_app.py"
    
    # Run scan
    report = run_scan(str(flask_file), framework_override="flask")
    
    # Assertions
    assert report.framework_detected == "flask"
    assert len(report.findings) > 0
    
    # Extract finding rule IDs
    rule_ids = {f.rule_id for f in report.findings}
    
    # Assert expected rules triggered
    assert "hardcoded-secret" in rule_ids
    assert "missing-try-except" in rule_ids
    assert "unprotected-route" in rule_ids
    assert "sql-injection" in rule_ids
    assert "rest-missing-status-404" in rule_ids
    assert "error-response-status-200" in rule_ids
    assert "error-only-logged" in rule_ids
    assert "command-injection" in rule_ids
    assert "weak-jwt-secret" in rule_ids
    assert "weak-jwt-missing-exp" in rule_ids
    assert "weak-jwt-algorithm" in rule_ids
    
    # Verify ignored secrets are NOT present
    ignored_findings = [f for f in report.findings if "SAFE_SECRET" in f.code_snippet]
    assert len(ignored_findings) == 0

def test_fastapi_app_audit():
    sample_dir = Path(__file__).parent / "sample_apps"
    fastapi_file = sample_dir / "fastapi_app.py"
    
    # Run scan
    report = run_scan(str(fastapi_file), framework_override="fastapi")
    
    # Assertions
    assert report.framework_detected == "fastapi"
    assert len(report.findings) > 0
    
    # Extract finding rule IDs
    rule_ids = {f.rule_id for f in report.findings}
    
    assert "hardcoded-secret" in rule_ids
    assert "sql-injection" in rule_ids
    assert "rest-missing-status-404" in rule_ids
    assert "unprotected-route" in rule_ids
    assert "rest-missing-status-401" in rule_ids
