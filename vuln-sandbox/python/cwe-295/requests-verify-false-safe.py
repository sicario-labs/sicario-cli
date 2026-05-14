# SAFE: requests-verify-false — SSL certificate verification enabled (default)
# Rule: PyRequestsVerifyFalse | CWE-295 | Expected: TrueNegative

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/proxy')
def proxy():
    target = 'https://api.example.com/data'

    # SAFE: verify=True is the default; certificate verification is enabled
    response = requests.get(target, timeout=10)
    return jsonify({'status': response.status_code, 'data': response.json()})


if __name__ == '__main__':
    app.run()
