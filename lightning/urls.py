from django.urls import path
from .views import (
    LightningBalanceAPIView,
    LightningTransactionsAPIView,
    LightningInvoiceCreateAPIView,
    LightningInvoiceDetailAPIView,
    LightningPaymentAPIView
)

urlpatterns = [
    path('lightning/balance/', LightningBalanceAPIView.as_view(), name='lightning_balance'),
    path('lightning/transactions/', LightningTransactionsAPIView.as_view(), name='lightning_transactions'),
    path('lightning/invoices/', LightningInvoiceCreateAPIView.as_view(), name='lightning_invoice_create'),
    path('lightning/invoices/<int:invoice_id>/', LightningInvoiceDetailAPIView.as_view(), name='lightning_invoice_detail'),
    path('lightning/payments/', LightningPaymentAPIView.as_view(), name='lightning_payment'),
]
