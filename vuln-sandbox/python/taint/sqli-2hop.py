# Taint: SQL Injection — 2-hop (Python)
# Source: request.args.get('id') → intermediate: find_user() → Sink: cursor.execute
# Expected: TruePositive (taint/cwe89)
from flask import Flask, request
import sqlite3

app = Flask(__name__)

def find_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SINK
    return cursor.fetchone()

@app.route('/user')
def get_user():
    user_id = request.args.get('id')           # SOURCE: HTTP request param
    return str(find_user(user_id))             # INTERMEDIATE: passes taint
