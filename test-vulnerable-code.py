# Intentionally vulnerable Python code for testing PR scan workflow

import os
import subprocess
import pickle

# Command injection via os.system (py-os-system)
def run_command(user_input):
    os.system("ls " + user_input)

# Command injection via os.popen (py-os-popen)
def read_output(filename):
    os.popen("cat " + filename)

# Dangerous exec usage (py-exec-usage)
def execute_code(code):
    exec(code)

# Dangerous eval usage (py-eval-usage)
def evaluate(expression):
    return eval(expression)

# Unsafe deserialization (py-pickle-loads)
def load_data(data):
    return pickle.loads(data)

# subprocess with shell=True (py-subprocess-shell-true)
def run_shell(cmd):
    subprocess.run(cmd, shell=True)
