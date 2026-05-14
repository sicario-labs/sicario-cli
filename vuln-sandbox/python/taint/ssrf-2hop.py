# Taint: SSRF — 2-hop (Python)
# Source: request.args.get('endpoint') → intermediate: fetch() → Sink: requests.post
# Expected: TruePositive (taint/cwe918)
from flask import Flask, request
import requests

app = Flask(__name__)

def fetch(endpoint):
    return requests.post(endpoint, json={})    # SINK: outbound HTTP request

@app.route('/fetch')
def do_fetch():
    endpoint = request.args.get('endpoint')    # SOURCE: HTTP request param
    return fetch(endpoint).text                # INTERMEDIATE
