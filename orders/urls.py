from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProviderViewSet, OrderViewSet, CalculateFeeView

router = DefaultRouter()
router.register("providers", ProviderViewSet, basename="provider")
router.register("orders", OrderViewSet, basename="order")

urlpatterns = [
    path("", include(router.urls)),
    path('providers/buy/calculate-fee/', CalculateFeeView.as_view(), name='calculate_fee'),
]

