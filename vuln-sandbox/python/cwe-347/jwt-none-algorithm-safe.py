# SAFE: jwt-none-algorithm — algorithm explicitly set to HS256; 'none' not accepted
# Rule: CryptoJwtNoneAlgorithm | CWE-347 | Expected: TrueNegative

import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = os.environ['JWT_SECRET']


@app.route('/verify')
def verify():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    if not token:
        return jsonify({'error': 'No token'}), 401

    # SAFE: algorithms list explicitly restricts to HS256; 'none' is not accepted
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    except jwt.InvalidTokenError as e:
        return jsonify({'error': str(e)}), 401

    return jsonify({'user': payload})


if __name__ == '__main__':
    app.run()
