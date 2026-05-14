# SAFE: unsafe-deserialize — JSON used instead of pickle for deserialization
# Rule: PyUnsafeDeserialize | CWE-502 | Expected: TrueNegative

import json
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/load', methods=['POST'])
def load_data():
    """Deserialize user-provided data using JSON (safe) instead of pickle (unsafe)."""
    raw = request.get_data(as_text=True)

    # SAFE: json.loads only parses data structures; it cannot execute arbitrary code
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400

    return jsonify({'received': data})


if __name__ == '__main__':
    app.run()
