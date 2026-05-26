from flask import Flask, jsonify, request
import jwt
import os
import sqlite3
import subprocess

app = Flask(__name__)

# 1. Hardcoded Secret (Should trigger critical finding)
JWT_SECRET = "super-secret-signature-key-987654321"

# 2. Hardcoded secret but ignored (Should NOT trigger finding)
SAFE_SECRET = "safe-entropy-value-but-ignored"  # backend-audit:ignore

# 3. Unprotected sensitive route (Should trigger high finding)
@app.route("/admin/dashboard")
def admin_dashboard():
    return jsonify(message="Welcome to admin panel")

# 4. Route lacking try-except (Should trigger medium finding)
@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    
    # 5. SQL Injection (Should trigger critical finding)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    
    # 6. Entity not found check returning 200 OK implicitly (Should trigger medium finding)
    if not user:
        return jsonify(error="User not found")
        
    return jsonify(id=user[0], name=user[1])

# 7. Error only logged & Status 200 returned in except block (Should trigger high error-response-status-200 and error-only-logged)
@app.route("/api/execute")
def run_command():
    cmd = request.args.get("cmd")
    try:
        # 8. Command injection (Should trigger critical finding)
        result = subprocess.run(f"echo {cmd}", shell=True, capture_output=True, text=True)
        return jsonify(output=result.stdout)
    except Exception as e:
        print(f"Error executing command: {e}")
        # Swallows error and returns implicit 200 OK!
        return jsonify(error="Failed to run command")

# 9. Weak JWT Implementation (Should trigger weak-jwt-missing-exp and weak-jwt-secret)
@app.route("/api/login")
def login():
    username = request.args.get("username")
    
    # Hardcoded secret & no expiration passed as literal
    token = jwt.encode({"sub": username}, "secret-key", algorithm="HS256")
    return jsonify(token=token)

# 10. Weak JWT none algorithm (Should trigger weak-jwt-algorithm)
@app.route("/api/token/unsafe")
def unsafe_token():
    payload = {"sub": "guest"}
    token = jwt.encode(payload, "key", algorithm="none")
    return jsonify(token=token)

# 11. Exception swallowing without return/raise (Should trigger error-only-logged)
@app.route("/api/swallowed")
def swallowed_route():
    try:
        x = 1 / 0
    except Exception as e:
        print("Swallowed:", e)

if __name__ == "__main__":
    app.run()
