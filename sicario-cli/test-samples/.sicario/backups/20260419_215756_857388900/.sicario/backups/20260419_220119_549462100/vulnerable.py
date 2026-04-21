# Sample Python file with intentional vulnerabilities for testing sicario

import subprocess
import pickle

password = "hunter2"
secret = "my-api-secret"

def run_command(user_input):
    # VULN: shell injection
    subprocess.run(user_input, shell=True)

def execute_code(code):
    # VULN: code injection
    exec(code)
    eval(code)

def load_data(file_path):
    # VULN: unsafe deserialization
    with open(file_path, "rb") as f:
        return pickle.load(f)

def check_admin(user):
    # VULN: assert used for security check
    assert user.role == "admin", "Not an admin"
    return True
