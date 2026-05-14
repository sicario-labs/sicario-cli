# SAFE: jwt-weak-algorithm — RS256 asymmetric algorithm used instead of weak HS256
# Rule: CryptoJwtWeakAlgorithm | CWE-327 | Expected: TrueNegative

import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# SAFE: RS256 asymmetric algorithm; private key signs, public key verifies
PRIVATE_KEY = open(os.environ['JWT_PRIVATE_KEY_PATH']).read()
PUBLIC_KEY = open(os.environ['JWT_PUBLIC_KEY_PATH']).read()


@app.route('/token', methods=['POST'])
def issue_token():
    user_id = request.json.get('user_id')
    token = jwt.encode({'sub': user_id}, PRIVATE_KEY, algorithm='RS256')
    return jsonify({'token': token})


@app.route('/verify')
def verify():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
    except jwt.InvalidTokenError as e:
        return jsonify({'error': str(e)}), 401
    return jsonify({'user': payload})


if __name__ == '__main__':
    app.run()
