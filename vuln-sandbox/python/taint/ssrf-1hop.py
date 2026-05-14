# Taint: SSRF — 1-hop (Python)
# Source: request.args.get('url') → Sink: requests.get
# Expected: TruePositive (taint/cwe918)
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')              # SOURCE: HTTP request param
    response = requests.get(url)               # SINK: outbound HTTP request
    return response.text
