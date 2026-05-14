# Taint: XSS — 1-hop (Python)
# Source: request.args.get('name') → Sink: render_template_string
# Expected: TruePositive (taint/cwe79)
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name')            # SOURCE: HTTP request param
    return render_template_string(f"<h1>Hello {name}</h1>")  # SINK: template rendering
