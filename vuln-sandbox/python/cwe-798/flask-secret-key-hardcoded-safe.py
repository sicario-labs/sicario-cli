# SAFE: flask-secret-key-hardcoded — secret key loaded from environment variable
# Rule: FlaskSecretKeyHardcoded | CWE-798 | Expected: TrueNegative

import os
from flask import Flask

app = Flask(__name__)

# SAFE: secret key loaded from environment variable; never hardcoded in source
app.secret_key = os.environ['FLASK_SECRET_KEY']

if not app.secret_key:
    raise ValueError('FLASK_SECRET_KEY environment variable must be set')

@app.route('/')
def index():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run()
