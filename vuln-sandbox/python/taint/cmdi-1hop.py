# Taint: Command Injection — 1-hop (Python)
# Source: request.args.get('cmd') → Sink: os.system
# Expected: TruePositive (taint/cwe78)
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')              # SOURCE: HTTP request param
    os.system(f"ls {cmd}")                     # SINK: shell command
    return 'done'
