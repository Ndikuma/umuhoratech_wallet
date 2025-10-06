from django.urls import path
from .views import (
    LightningBalanceAPIView,
    LightningTransactionsAPIView,
    LightningInvoiceCreateAPIView,
    LightningInvoiceDetailAPIView,
    LightningDecodeAPIView,
    LightningPaymentAPIView
)

urlpatterns = [
    path('lightning/balance/', LightningBalanceAPIView.as_view(), name='lightning_balance'),
    path('lightning/transactions/', LightningTransactionsAPIView.as_view(), name='lightning_transactions'),
    path('lightning/invoices/', LightningInvoiceCreateAPIView.as_view(), name='lightning_invoice_create'),
    path('lightning/invoices/<str:payment_hash>/', LightningInvoiceDetailAPIView.as_view(), name='lightning_invoice_detail'),
    path('lightning/payments/', LightningPaymentAPIView.as_view(), name='lightning_payment'),
    path("lightning/decode/", LightningDecodeAPIView.as_view(), name="lightning_decode")
]
