import sys
import os

project_home = '/home/btcshulevgfhnehg/repositories/umuhoratech_wallet'
sys.path.insert(0, project_home)

os.environ['DJANGO_SETTINGS_MODULE'] = 'mini_wallet.settings'

activate_env = '/home/btcshulevgfhnehg/virtualenv/repositories/umuhoratech_wallet/3.12/bin/activate_this.py'
with open(activate_env) as f:
    exec(f.read(), dict(__file__=activate_env))

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
