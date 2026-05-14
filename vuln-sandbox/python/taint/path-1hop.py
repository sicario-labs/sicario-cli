# Taint: Path Traversal — 1-hop (Python)
# Source: request.args.get('file') → Sink: open()
# Expected: TruePositive (taint/cwe22)
from flask import Flask, request

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')        # SOURCE: HTTP request param
    with open(f"/uploads/{filename}") as f:    # SINK: file open
        return f.read()
