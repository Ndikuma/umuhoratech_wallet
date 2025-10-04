from django.utils import timezone
from django.db import transaction
from .models import WalletLocal, Invoice
from .blink_wallet import BlinkWallet


class BlinkWalletService:
    def __init__(self, user):
        self.user = user
        self.client = BlinkWallet()  # uses BLINK_API_KEY
        self.wallet_local, _ = WalletLocal.objects.get_or_create(user=user)

    @transaction.atomic
    def create_invoice(self, amount: int) -> Invoice:
        """
        Create an LN invoice via Blink and store locally.
        """
        # Call Blink API
        remote_invoice = self.client.create_ln_invoice(amount)

        # Save invoice locally
        invoice = Invoice.objects.create(
            wallet=self.wallet_local,
            payment_request=remote_invoice["paymentRequest"],
            amount=remote_invoice.get("satoshis"),
            status="UNPAID"
        )
        return invoice

    @transaction.atomic
    def pay_invoice(self, payment_request: str, amount: int = None):
        """
        Pay invoice. If it's internal, handle locally.
        Otherwise forward to Blink.
        """
        # Try to see if it's internal
        try:
            invoice = Invoice.objects.select_for_update().get(payment_request=payment_request)
            internal = True
        except Invoice.DoesNotExist:
            invoice = None
            internal = False

        # Case 1: Internal payment
        if internal:
            if invoice.status != "UNPAID":
                return {"status": "FAILED", "error": "Invoice already processed"}

            if self.wallet_local.balance < invoice.amount:
                return {"status": "FAILED", "error": "Insufficient balance"}

            # Move sats internally
            self.wallet_local.subtract_balance(invoice.amount)
            invoice.wallet.add_balance(invoice.amount)
            invoice.mark_paid()

            return {
                "status": "SUCCESS",
                "type": "internal",
                "from": self.wallet_local.user.username,
                "to": invoice.wallet.user.username,
                "amount": invoice.amount,
            }

        # Case 2: External payment (use Blink)
        payment = self.client.pay_ln_invoice(payment_request, amount=amount)
        return {
            "status": payment["payment"].get("status"),
            "type": "external",
            "response": payment,
        }
