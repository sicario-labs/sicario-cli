# SAFE: ldap-injection — LDAP special characters escaped before filter construction
# Rule: InjectLdap | CWE-90 | Expected: TrueNegative

import ldap
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

LDAP_SPECIAL_CHARS = re.compile(r'[\\*\(\)\x00]')


def escape_ldap_filter(value: str) -> str:
    """Escape LDAP filter special characters per RFC 4515."""
    replacements = {'\\': '\\5c', '*': '\\2a', '(': '\\28', ')': '\\29', '\x00': '\\00'}
    return LDAP_SPECIAL_CHARS.sub(lambda m: replacements[m.group()], value)


@app.route('/user')
def get_user():
    username = request.args.get('username', '')

    conn = ldap.initialize('ldap://localhost:389')
    conn.simple_bind_s('cn=admin,dc=example,dc=com', 'admin_password')

    # SAFE: username escaped before being used in the LDAP filter
    safe_username = escape_ldap_filter(username)
    ldap_filter = f'(uid={safe_username})'

    results = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, ldap_filter)
    conn.unbind_s()

    return jsonify([{'dn': dn, 'attrs': attrs} for dn, attrs in results])


if __name__ == '__main__':
    app.run()
