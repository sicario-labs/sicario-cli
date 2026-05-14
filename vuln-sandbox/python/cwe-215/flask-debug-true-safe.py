# SAFE: flask-debug-true — debug mode disabled in production
# Rule: FlaskDebugTrue | CWE-215 | Expected: TrueNegative

import os
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, World!'

if __name__ == '__main__':
    # SAFE: debug mode controlled by environment variable; defaults to False
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
