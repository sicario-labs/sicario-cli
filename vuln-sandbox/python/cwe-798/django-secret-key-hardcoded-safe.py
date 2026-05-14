# SAFE: django-secret-key-hardcoded — SECRET_KEY loaded from environment variable
# Rule: DjangoSecretKeyHardcoded | CWE-798 | Expected: TrueNegative

import os

# SAFE: SECRET_KEY loaded from environment variable; never hardcoded in source
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

if not SECRET_KEY:
    raise ValueError('DJANGO_SECRET_KEY environment variable must be set')

DEBUG = False
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
