# SAFE: django-allowed-hosts-wildcard — ALLOWED_HOSTS set to specific domains
# Rule: DjangoAllowedHostsWildcard | CWE-183 | Expected: TrueNegative

import os

# SAFE: ALLOWED_HOSTS set to specific domains; wildcard '*' is not used
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'example.com,www.example.com').split(',')

DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
