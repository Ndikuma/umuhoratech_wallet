import sys
import os

# Add your project directory to sys.path (adjust the path for your server)
sys.path.insert(0, '/home/btcshulevgfhnehg/repositories/umuhoratech_wallet')

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mini_wallet.settings")


from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
