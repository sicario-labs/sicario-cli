# Taint: Path Traversal — 2-hop (Python)
# Source: request.args.get('name') → intermediate: read_file() → Sink: open()
# Expected: TruePositive (taint/cwe22)
from flask import Flask, request

app = Flask(__name__)

def read_file(name):
    with open(f"/data/{name}") as f:           # SINK: file open
        return f.read()

@app.route('/file')
def get_file():
    name = request.args.get('name')            # SOURCE: HTTP request param
    return read_file(name)                     # INTERMEDIATE
