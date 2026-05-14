# SAFE: xpath-injection — user input validated as integer before use in XPath
# Rule: InjectXpath | CWE-643 | Expected: TrueNegative

from lxml import etree
from flask import Flask, request, jsonify

app = Flask(__name__)

XML_DATA = b"""
<users>
  <user id="1"><name>Alice</name><email>alice@example.com</email></user>
  <user id="2"><name>Bob</name><email>bob@example.com</email></user>
</users>
"""

tree = etree.fromstring(XML_DATA)


@app.route('/user')
def get_user():
    user_id = request.args.get('id', '')

    # SAFE: validate that id is a positive integer before using in XPath
    if not user_id.isdigit():
        return jsonify({'error': 'Invalid user ID'}), 400

    # SAFE: integer-validated ID used in XPath; no arbitrary string interpolation
    nodes = tree.xpath(f'/users/user[@id="{int(user_id)}"]/name')
    names = [n.text for n in nodes]
    return jsonify({'names': names})


if __name__ == '__main__':
    app.run()
