# SAFE: password-in-log — password field excluded from log output
# Rule: AuthPasswordInLog | CWE-532 | Expected: TrueNegative

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

SENSITIVE_FIELDS = {'password', 'token', 'secret', 'api_key', 'authorization'}


def sanitize_for_log(data: dict) -> dict:
    """Return a copy of data with sensitive fields redacted."""
    return {k: '[REDACTED]' if k.lower() in SENSITIVE_FIELDS else v for k, v in data.items()}


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # SAFE: log only the sanitized request; password is never written to logs
    logger.info('Login attempt: %s', sanitize_for_log(data))

    username = data.get('username')
    password = data.get('password')

    if username == 'admin' and password == 'correct-password':
        return jsonify({'token': 'jwt-token-here'})
    return jsonify({'error': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run()
