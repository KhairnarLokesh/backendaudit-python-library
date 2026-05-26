import os
from flask import Flask, render_template, jsonify, request
from backend_audit.scanner import run_scan

app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    path = data.get("path", ".")
    framework = data.get("framework") or None
    
    try:
        report = run_scan(path, framework_override=framework)
        return jsonify(report.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("-" * 60)
    print("[SERVER] backend-audit Dashboard Server started on http://127.0.0.1:5000")
    print("[SECURE] 100% Offline and Local Data Privacy Guaranteed")
    print("-" * 60)
    app.run(debug=True, port=5000)
