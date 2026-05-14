# SAFE: ssti — render_template used with a static template file, not render_template_string
# Rule: InjectSsti | CWE-94 | Expected: TrueNegative

from flask import Flask, request, render_template

app = Flask(__name__)


@app.route('/greet')
def greet():
    """Render a greeting using a static template file."""
    name = request.args.get('name', 'World')

    # SAFE: render_template loads a static file from the templates/ directory;
    # user input is passed as a context variable, not embedded in the template string
    return render_template('greet.html', name=name)


if __name__ == '__main__':
    app.run()

# templates/greet.html would contain:
# <h1>Hello, {{ name }}!</h1>
# Jinja2 auto-escapes {{ name }} by default, preventing XSS as well
