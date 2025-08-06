"""
Professional URL routing for Bitcoin Mini Wallet API.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from .viewsets import AuthViewSet, UserViewSet, WalletViewSet, TransactionViewSet

app_name = 'wallet'  # App namespace

# Create DRF router and register viewsets
router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserViewSet, basename='user')
router.register(r'wallets', WalletViewSet, basename='wallet')
router.register(r'transactions', TransactionViewSet, basename='transaction')

# Main URL patterns
urlpatterns = [
    # Versioned API routes
        path('', include(router.urls)),
        # API schema and docs
        path('schema/', SpectacularAPIView.as_view(), name='schema'),
        path('docs/', SpectacularSwaggerView.as_view(url_name='wallet:schema'), name='swagger-ui'),
        path('redoc/', SpectacularRedocView.as_view(url_name='wallet:schema'), name='redoc'),
  
]
