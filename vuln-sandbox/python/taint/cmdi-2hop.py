# Taint: Command Injection — 2-hop (Python)
# Source: request.form.get('filename') → intermediate: process() → Sink: subprocess.run
# Expected: TruePositive (taint/cwe78)
from flask import Flask, request
import subprocess

app = Flask(__name__)

def process(filename):
    subprocess.run(f"convert {filename} output.png", shell=True)  # SINK

@app.route('/convert', methods=['POST'])
def convert():
    filename = request.form.get('filename')    # SOURCE: HTTP request form
    process(filename)                          # INTERMEDIATE
    return 'converted'
