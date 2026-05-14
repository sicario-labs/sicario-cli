# Taint: XSS — 2-hop (Python)
# Source: request.args.get('msg') → intermediate: build_page() → Sink: Markup
# Expected: TruePositive (taint/cwe79)
from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)

def build_page(msg):
    return Markup(f"<div>{msg}</div>")         # SINK: unescaped HTML markup

@app.route('/message')
def message():
    msg = request.args.get('msg')              # SOURCE: HTTP request param
    return build_page(msg)                     # INTERMEDIATE
