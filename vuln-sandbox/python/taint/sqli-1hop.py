# Taint: SQL Injection — 1-hop (Python)
# Source: request.args.get('id') → Sink: cursor.execute
# Expected: TruePositive (taint/cwe89)
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')           # SOURCE: HTTP request param
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SINK
    return str(cursor.fetchall())
