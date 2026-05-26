from fastapi import FastAPI, Depends, HTTPException, Query
import os
import sqlite3

app = FastAPI()

# 1. Missing Try/Except & SQL Injection inside async route (Should trigger medium and critical findings)
@app.get("/api/items/{item_id}")
async def read_item(item_id: int):
    conn = sqlite3.connect("items.db")
    cursor = conn.cursor()
    
    # SQLi
    cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")
    item = cursor.fetchone()
    
    # 2. Entity Not Found returning 200 OK (Should trigger medium rest-missing-status-404)
    if not item:
        return {"error": "Item not found"}
        
    return {"id": item[0], "name": item[1]}

# 3. Unprotected sensitive route starts with /api/private (Should trigger high unprotected-route)
@app.get("/api/private/config")
def get_private_config():
    # 4. Hardcoded Secret (Should trigger critical finding)
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    return {"aws_key": aws_key}

# 5. Auth validation mismatch (Should trigger rest-missing-status-401/403)
@app.get("/api/user/profile")
def get_profile(token: str = Query(None)):
    # Explicit check for auth token
    if not token:
        # returns 200 OK implicitly
        return {"error": "Unauthorized"}
        
    return {"user": "Alice"}
