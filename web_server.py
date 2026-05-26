import os
import ast
import time
from pathlib import Path
from flask import Flask, jsonify, request, render_template, send_from_directory

from src.backend_audit.models import AuditReport, Finding
from src.backend_audit.rules import ErrorHandlingRule, SecurityRule, RestValidationRule
from src.backend_audit.utils.comments import get_ignored_lines

app = Flask(__name__, template_folder="templates", static_folder="static")

# Sample Vulnerable Templates to populate the editor
TEMPLATES = {
    "flask": '''from flask import Flask, jsonify, request
import sqlite3
import jwt

app = Flask(__name__)
JWT_SECRET = "super-secret-signature-key-987654321"

@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    
    # Vulnerable SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    
    if not user:
        # Implicit 200 OK returned on error
        return jsonify(error="User not found")
        
    return jsonify(id=user[0], name=user[1])
''',
    "fastapi": '''from fastapi import FastAPI, HTTPException
import sqlite3

app = FastAPI()

@app.get("/api/items/{item_id}")
async def read_item(item_id: int):
    conn = sqlite3.connect("items.db")
    cursor = conn.cursor()
    
    # Vulnerable SQL Injection
    cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")
    item = cursor.fetchone()
    
    if not item:
        # Returns implicit 200 OK instead of 404
        return {"error": "Item not found"}
        
    return {"id": item[0], "name": item[1]}
''',
    "django": '''from django.http import JsonResponse
from django.db import connection

# Django Unprotected view view_delete
def view_delete(request):
    user_id = request.GET.get("id")
    cursor = connection.cursor()
    
    # Vulnerable SQL Injection
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    
    # Missing try/except, returns 200 OK implicitly on error
    return JsonResponse({"status": "user deleted"})
'''
}

@app.route("/")
def index():
    """Renders the frontend dashboard."""
    return render_template("index.html")

@app.route("/api/templates", methods=["GET"])
def get_templates():
    """Serves sample code templates."""
    return jsonify(TEMPLATES)

@app.route("/api/scan", methods=["POST"])
def scan_code():
    """
    Scans the posted code block locally using the backend-audit static analysis engine.
    No network requests or cloud AI boundaries are crossed.
    """
    start_time = time.time()
    data = request.get_json() or {}
    code = data.get("code", "")
    framework = data.get("framework", "flask")

    if not code.strip():
        return jsonify({
            "scanned_files": ["sandbox.py"],
            "findings": [],
            "framework_detected": framework,
            "scan_time_seconds": 0.0
        })

    # Instantiate rules
    rules = [
        ErrorHandlingRule(),
        SecurityRule(),
        RestValidationRule()
    ]

    findings = []
    
    # Parse code locally
    try:
        tree = ast.parse(code, filename="sandbox.py")
        ignored_lines = get_ignored_lines(code)

        # Run each rule
        for rule in rules:
            try:
                rule_findings = rule.run(
                    tree=tree,
                    code=code,
                    file_path="sandbox.py",
                    ignored_lines=ignored_lines,
                    framework=framework
                )
                for f in rule_findings:
                    if f.line not in ignored_lines:
                        findings.append(f)
            except Exception as e:
                findings.append(Finding(
                    rule_id="rule-execution-error",
                    severity="high",
                    message=f"Rule {rule.rule_id} crashed: {str(e)}",
                    file_path="sandbox.py",
                    line=1,
                    column=0,
                    code_snippet=""
                ))
    except SyntaxError as e:
        findings.append(Finding(
            rule_id="python-syntax-error",
            severity="critical",
            message=f"Python syntax error prevents static scanning: {e.msg}",
            file_path="sandbox.py",
            line=e.lineno or 1,
            column=e.offset or 0,
            code_snippet=f"Line {e.lineno}: {e.text.strip() if e.text else ''}"
        ))

    scan_time = time.time() - start_time
    
    report = AuditReport(
        scanned_files=["sandbox.py"],
        findings=findings,
        framework_detected=framework,
        scan_time_seconds=round(scan_time, 4)
    )

    return jsonify(report.to_dict())

if __name__ == "__main__":
    print("------------------------------------------------------------")
    print("[SERVER] backend-audit Dashboard Server started on http://127.0.0.1:5000")
    print("[SECURE] 100% Offline and Local Data Privacy Guaranteed")
    print("------------------------------------------------------------")
    app.run(debug=True, port=5000)
