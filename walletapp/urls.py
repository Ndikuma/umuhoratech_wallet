from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AuthViewSet, UserViewSet, WalletViewSet, TransactionViewSet 
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

# Create a router for viewsets
router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'user', UserViewSet, basename='user')
router.register(r'wallet', WalletViewSet, basename='wallet')
router.register(r'transaction', TransactionViewSet, basename='transaction')

# URL patterns
urlpatterns = [
    # Router-generated URLs for viewsets
    path('', include(router.urls)),
    
    # Specific action endpoints (optional, for clarity or custom paths)
    path('auth/register/', AuthViewSet.as_view({'post': 'register'}), name='auth-register'),
    path('auth/login/', AuthViewSet.as_view({'post': 'login'}), name='auth-login'),
    path('auth/logout/', AuthViewSet.as_view({'post': 'logout'}), name='auth-logout'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

]