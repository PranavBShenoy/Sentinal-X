"""
INTENTIONALLY VULNERABLE SQL INJECTION FIXTURE.
FOR TESTING ONLY — DO NOT USE IN PRODUCTION.
Used to verify Semgrep SAST detection of direct string formatting in SQL queries.
"""
import sqlite3
from fastapi import FastAPI, Query

app = FastAPI(title="Vulnerable SQLi App", version="1.0.0")


@app.get("/users")
def get_user(username: str = Query(...)):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")

    # INTENTIONAL VULNERABILITY FOR TESTING: Unsafe string interpolation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"  # nosec
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return {"users": results}
