# SAFE: command-injection — subprocess called with a list (no shell=True) and allowlist
# Rule: InjectPythonSubprocessShell | CWE-78 | Expected: TrueNegative

import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_COMMANDS = {'ping', 'date', 'uptime'}


@app.route('/run', methods=['GET'])
def run_command():
    """Run a whitelisted command without shell injection risk."""
    cmd = request.args.get('cmd', '')

    # SAFE: command validated against allowlist; shell=False (default) prevents metacharacter injection
    if cmd not in ALLOWED_COMMANDS:
        return jsonify({'error': 'Command not allowed'}), 400

    result = subprocess.run([cmd], capture_output=True, text=True, timeout=5)
    return jsonify({'output': result.stdout, 'returncode': result.returncode})


if __name__ == '__main__':
    app.run()
