from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from .services import BlinkWalletService
from .models import WalletLocal, Invoice

# -------------------------------
# Lightning Balance
# -------------------------------
class LightningBalanceAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        wallet, _ = WalletLocal.objects.get_or_create(user=request.user)
        return Response({
            "balance": wallet.balance,
            "currency": "sats"
        })


# -------------------------------
# Lightning Transactions / Invoices
# -------------------------------
class LightningTransactionsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        invoices = Invoice.objects.filter(wallet__user=request.user).order_by("-created_at")
        data = [{
            "id": inv.id,
            "amount": inv.amount,
            "status": inv.status,
            "payment_request": inv.payment_request,
            "created_at": inv.created_at,
            "paid_at": inv.paid_at
        } for inv in invoices]
        return Response({
            "results": data,
            "count": invoices.count()
        })


# -------------------------------
# Generate Lightning Invoice
# -------------------------------
class LightningInvoiceCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        amount = request.data.get("amount")
        if not amount:
            return Response({"error": "Amount is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = int(amount)
        except ValueError:
            return Response({"error": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

        service = BlinkWalletService(user=request.user)
        invoice = service.create_invoice(amount)

        return Response({
            "amount": invoice.amount,
            "id": invoice.id,
            "payment_request": invoice.payment_request,
            "payment_request_qr":service.client.generate_qr(invoice.payment_request),
            "status": invoice.status
        })


# -------------------------------
# Get Lightning Invoice Details
# -------------------------------
class LightningInvoiceDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, invoice_id):
        invoice = get_object_or_404(Invoice, id=invoice_id, wallet__user=request.user)
        return Response({
            "id": invoice.id,
            "amount": invoice.amount,
            "payment_request": invoice.payment_request,
            "status": invoice.status,
            "created_at": invoice.created_at,
            "paid_at": invoice.paid_at
        })


# -------------------------------
# Pay Lightning Invoice
# -------------------------------
class LightningPaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payment_request = request.data.get("payment_request")
        amount = request.data.get("amount")  # optional for zero-amount invoices

        if not payment_request:
            return Response({"error": "Payment request is required"}, status=status.HTTP_400_BAD_REQUEST)

        if amount:
            try:
                amount = int(amount)
            except ValueError:
                return Response({"error": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

        service = BlinkWalletService(user=request.user)
        result = service.pay_invoice(payment_request, amount=amount)

        return Response(result)
