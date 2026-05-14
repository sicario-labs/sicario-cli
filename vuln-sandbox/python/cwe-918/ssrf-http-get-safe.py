# SAFE: ssrf-http-get — URL validated against allowlist before making outbound request
# Rule: SsrfHttpGetUserInput | CWE-918 | Expected: TrueNegative

import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {'api.example.com', 'data.example.com', 'cdn.example.com'}


@app.route('/fetch')
def fetch_data():
    target_url = request.args.get('url', '')

    # SAFE: parse and validate the URL against an allowlist of trusted hosts
    try:
        parsed = urlparse(target_url)
    except Exception:
        return jsonify({'error': 'Invalid URL'}), 400

    if parsed.scheme not in ('http', 'https') or parsed.hostname not in ALLOWED_HOSTS:
        return jsonify({'error': 'URL not allowed'}), 400

    response = requests.get(target_url, timeout=5)
    return jsonify({'status': response.status_code, 'body': response.text[:1000]})


if __name__ == '__main__':
    app.run()
