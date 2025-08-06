"""
Main URL configuration for Bitcoin Mini Wallet API.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    # API endpoints
    path('', include('wallet.urls')),
    # Health check endpoint
    path('health/', lambda request: JsonResponse({'status': 'healthy'}), name='health-check'),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers
handler400 = 'wallet.views.custom_400'
handler403 = 'wallet.views.custom_403'
handler404 = 'wallet.views.custom_404'
handler500 = 'wallet.views.custom_500'