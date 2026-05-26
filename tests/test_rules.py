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

    # Verify status code meanings are present in rest findings
    rest_findings = [f for f in report.findings if f.rule_id == "rest-missing-status-404"]
    assert len(rest_findings) > 0
    assert "Meaning: Not Found -" in rest_findings[0].message

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

def test_http_status_descriptions():
    from backend_audit.rules.rest_validation import HTTP_STATUS_DESCRIPTIONS
    
    # Test checking specific standard codes across groups
    assert HTTP_STATUS_DESCRIPTIONS[100] == "100 - Continue"
    assert HTTP_STATUS_DESCRIPTIONS[200] == "200 - OK"
    assert HTTP_STATUS_DESCRIPTIONS[201] == "201 - Created"
    assert HTTP_STATUS_DESCRIPTIONS[301] == "301 - Moved Permanently"
    assert HTTP_STATUS_DESCRIPTIONS[302] == "302 - Found"
    assert HTTP_STATUS_DESCRIPTIONS[400] == "400 - Bad Request"
    assert HTTP_STATUS_DESCRIPTIONS[401] == "401 - Unauthorized"
    assert HTTP_STATUS_DESCRIPTIONS[403] == "403 - Forbidden"
    assert HTTP_STATUS_DESCRIPTIONS[404] == "404 - Not Found"
    assert HTTP_STATUS_DESCRIPTIONS[405] == "405 - Method Not Allowed"
    assert HTTP_STATUS_DESCRIPTIONS[429] == "429 - Too Many Requests"
    assert HTTP_STATUS_DESCRIPTIONS[500] == "500 - Internal Server Error"
    assert HTTP_STATUS_DESCRIPTIONS[503] == "503 - Service Unavailable"

    # Verify standard range is populated
    for code in [100, 101, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
                 300, 301, 302, 303, 304, 305, 307, 308, 400, 401, 402, 403, 404, 405,
                 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421,
                 422, 423, 424, 425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504,
                 505, 506, 507, 508, 510, 511]:
        assert code in HTTP_STATUS_DESCRIPTIONS
        assert HTTP_STATUS_DESCRIPTIONS[code].startswith(str(code))

def test_ignore_boolean_and_out_of_range_statuses():
    import ast
    from backend_audit.rules.rest_validation import RestValidationRule
    
    rule = RestValidationRule()
    # Mock visitor run
    code = """
def my_func():
    return True
def my_func2():
    return False
def my_func3():
    return 0
def my_func4():
    return 1
def my_func5():
    return 130
def my_func6():
    return 200
"""
    tree = ast.parse(code)
    findings = rule.run(tree, code, "dummy.py", set(), "flask")
    
    # We should only find status 200
    catalog_findings = [f for f in findings if f.rule_id == "rest-status-code-catalog"]
    assert len(catalog_findings) == 1
    assert "200 - OK" in catalog_findings[0].message
