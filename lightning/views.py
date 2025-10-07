from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from .services import BlinkWalletService
from .models import WalletLocal, Invoice
import requests

# -------------------------------
# Lightning Balance
# -------------------------------
class LightningBalanceAPIView(APIView):
    permission_classes = [IsAuthenticated]

    
    def get(self, request):
        wallet, _ = WalletLocal.objects.get_or_create(user=request.user)
        balance_sats = wallet.balance
        balance_btc = balance_sats / 100_000_000

        balance_usd = None
        balance_bif = None

        # Fetch USD value
        try:
            url_usd = f"https://api.yadio.io/convert/{balance_btc}/BTC/USD"
            balance_usd = round(requests.get(url_usd).json().get('result', 0), 2)
        except Exception:
            balance_usd = None

        # Fetch BIF value (USD -> BIF)
        if balance_usd:
            try:
                url_bif = f"https://api.yadio.io/convert/{balance_usd}/USD/BIF"
                balance_bif = round(requests.get(url_bif).json().get('result', 0), 2)
            except Exception:
                balance_bif = None

        return Response({
            "balance": balance_sats,
            "currency": "sats",
            "balance_usd": balance_usd,
            "balance_bif": balance_bif
        })



class LightningTransactionsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch invoices for this user
        invoices = Invoice.objects.filter(wallet__user=request.user).order_by('-created_at')

        transactions = []
        for inv in invoices:
            # Determine type: incoming vs outgoing
            tx_type = 'outgoing' if inv.is_outgoing else 'incoming'

           
            transactions.append({
                "type": tx_type,
                "amount_sats": inv.amount or 0,
                "fee_sats": 0,              # Replace with real fee if available
                "memo": inv.memo or "",     # Use memo stored in Invoice
                "status": inv.status.lower(),
                "created_at":inv.created_at.replace(microsecond=0).isoformat() + "Z",
                "payment_hash": inv.payment_hash or "",
                "bolt11": inv.payment_request or "",
                "expires_at": inv.expires_at.replace(microsecond=0).isoformat() + "Z" if inv.expires_at else None,
                "qr_code": inv.qr_code or None
            })

        return Response(transactions)

# -------------------------------
# Generate Lightning Invoice
# -------------------------------
from datetime import datetime, timedelta
import time

class LightningInvoiceCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        amount = request.data.get("amount")
        memo = request.data.get("memo", None)

        if not amount:
            return Response({"error": "Amount is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            amount = int(amount)
        except ValueError:
            return Response({"error": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

        service = BlinkWalletService(user=request.user)
        ln_invoice = service.create_invoice(amount, memo=memo)

        # created_at from invoice
        created_at = ln_invoice.created_at or datetime.utcnow()

        # expires_at from invoice or default 1h
        expires_at = ln_invoice.expires_at or (created_at + timedelta(seconds=9000))

        # Generate QR
        qr_code = ln_invoice.qr_code or service.generate_qr(ln_invoice.payment_request)

        response_data = {
            "payment_hash": ln_invoice.payment_hash,
            "bolt11": ln_invoice.payment_request,
            "amount_sats": ln_invoice.amount,
            "memo": ln_invoice.memo or memo or "",
            "status": ln_invoice.status,
            "created_at": created_at.isoformat() + "Z",
            "expires_at": expires_at.isoformat() + "Z",
            "qr_code": qr_code,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


# -------------------------------
# Get Lightning Invoice Details
# -------------------------------
class LightningInvoiceDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, payment_hash):
        try:
            invoice = Invoice.objects.get(payment_hash=payment_hash, wallet__user=request.user)
        except Invoice.DoesNotExist:
            return Response({"error": "Invoice not found"}, status=status.HTTP_404_NOT_FOUND)

        tx_type = "outgoing" if invoice.is_outgoing else "incoming"


        response_data = {
            "payment_hash": invoice.payment_hash,
            "bolt11": invoice.payment_request,
            "amount_sats": invoice.amount or 0,
            "memo": invoice.memo,
            "status": invoice.status,
            "type": tx_type,
            "created_at": invoice.created_at.isoformat() + "Z",
            "expires_at": invoice.expires_at.isoformat() + "Z" if invoice.expires_at else None,
            "paid_at": invoice.paid_at.isoformat() + "Z" if invoice.paid_at else None,
            "is_outgoing": invoice.is_outgoing,
        }

        return Response(response_data, status=status.HTTP_200_OK)


class LightningPaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles Lightning payments:
        - type: 'invoice', 'ln_address', 'lnurl'
        - request: payment_request for invoice
        - ln_address: LN address string
        - lnurl: LNURL string
        - amount: optional for zero-amount invoices, required for LN Address/LNURL
        - internal: boolean (for internal invoice payments)
        """
        payment_type = request.data.get("type")
        amount = request.data.get("amount_sats")
        internal = request.data.get("internal", False)

        service = BlinkWalletService(user=request.user)

        # Validate type
        if payment_type not in ("invoice", "ln_address", "lnurl"):
            return Response({"error": "Invalid payment type"}, status=status.HTTP_400_BAD_REQUEST)

        # Handle amount
        if amount is not None:
            try:
                amount = int(amount)
            except ValueError:
                return Response({"error": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)

        # ---------------------------
        # Payment logic by type
        # ---------------------------
        if payment_type == "invoice":
            payment_request = request.data.get("request")
            if not payment_request:
                return Response({"error": "Payment request is required"}, status=status.HTTP_400_BAD_REQUEST)

            result = service.pay_invoice(payment_request, amount=amount)
            return Response(result)

        elif payment_type == "ln_address":
            ln_address = request.data.get("request")
            if not ln_address:
                return Response({"error": "LN Address is required"}, status=status.HTTP_400_BAD_REQUEST)
            if not amount:
                return Response({"error": "Amount is required for LN Address payment"}, status=status.HTTP_400_BAD_REQUEST)

            result = service.pay_ln_address(ln_address, amount)
            return Response(result)

        elif payment_type == "lnurl":
            lnurl = request.data.get("lnurl")
            if not lnurl:
                return Response({"error": "LNURL is required"}, status=status.HTTP_400_BAD_REQUEST)
            if not amount:
                return Response({"error": "Amount is required for LNURL payment"}, status=status.HTTP_400_BAD_REQUEST)

            result = service.pay_lnurl(lnurl, amount)
            return Response(result)
        

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
import bolt11
import requests
from datetime import datetime, timedelta
import time

class LightningDecodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print(request.data)
        value = request.data.get("request")
        if not value:
            return Response({"error": "value is required"}, status=status.HTTP_400_BAD_REQUEST)

        decoded = {
            "type": None,
            "amount_sats": None,
            "amount_usd": None,
            "amount_bif": None,
            "fee_sats": None,
            "memo": None,
            "payee_pubkey": None,
            "expires_at": None,
            "internal": False,
            "status": None,
            "created_at": None,
            "payment_hash": None,
        }

        try:
            # -------------------------
            # BOLT11 Invoice
            # -------------------------
            if value.lower().startswith("lnbc") or value.lower().startswith("lntb"):
                decoded["type"] = "invoice"

                # Check if internal invoice
                try:
                    invoice_obj = Invoice.objects.get(payment_request=value, wallet__user=request.user)
                    decoded["internal"] = True
                    decoded["amount_sats"] = invoice_obj.amount
                    decoded["memo"] = getattr(invoice_obj, "memo", None)
                    decoded["payment_hash"] = getattr(invoice_obj, "payment_request", None)
                    decoded["status"] = invoice_obj.status.lower()
                    decoded["created_at"] = invoice_obj.created_at.isoformat() + "Z"
                    decoded["payee_pubkey"]=invoice_obj.wallet.user.username  # Placeholder
                    decoded["fee_sats"] = 0  # If you track fees, set
                    

                    # Optional: expires_at (if unpaid, assume 1 hour expiry)
                    if invoice_obj.status == "UNPAID":
                        decoded["expires_at"] = (invoice_obj.created_at + timedelta(hours=1)).isoformat() + "Z"

                except Invoice.DoesNotExist:
                    # External invoice → decode with bolt11
                    invoice = bolt11.decode(value)
                    decoded["internal"] = False
                    decoded["amount_sats"] = invoice.amount_msat // 1000 if invoice.amount_msat else None
                    decoded["memo"] = getattr(invoice, "description", None)
                    decoded["payee_pubkey"] = getattr(invoice, "payee", None)

                    created = invoice.date
                    expiry = invoice.expiry
                    decoded["expires_at"] = datetime.utcfromtimestamp(created + expiry).isoformat() + "Z"

                    # Convert to USD/BIF
                    if decoded["amount_sats"]:
                        btc_amount = decoded["amount_sats"] / 100_000_000
                        try:
                            url_usd = f"https://api.yadio.io/convert/{btc_amount}/BTC/USD"
                            decoded["amount_usd"] = round(requests.get(url_usd).json().get('result', 0), 2)
                            url_bif = f"https://api.yadio.io/convert/{decoded['amount_usd']}/USD/BIF"
                            decoded["amount_bif"] = round(requests.get(url_bif).json().get('result', 0), 2)
                        except Exception:
                            decoded["amount_usd"] = None
                            decoded["amount_bif"] = None

            # -------------------------
            # LNURL
            # -------------------------
            elif value.lower().startswith("lnurl"):
                decoded["type"] = "lnurl"

            # -------------------------
            # Lightning Address
            # -------------------------
            elif "@" in value:
                decoded["type"] = "ln_address"
                decoded["payee_pubkey"] = value
                

            else:
                return Response({"error": "Unknown Lightning request type"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": f"Failed to decode: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(decoded)