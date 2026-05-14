# SAFE: jwt-no-expiry — JWT issued with an expiration time
# Rule: AuthJwtNoExpiry | CWE-613 | Expected: TrueNegative

import os
import time
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = os.environ['JWT_SECRET']


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')

    # SAFE: exp claim set to 1 hour from now; token will expire and cannot be used indefinitely
    payload = {
        'sub': username,
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,  # 1 hour
    }
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return jsonify({'token': token})


if __name__ == '__main__':
    app.run()
