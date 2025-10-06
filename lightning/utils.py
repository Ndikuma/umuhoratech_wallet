from django.db import transaction
from django.utils import timezone
from .models import Invoice, WalletLocal

@transaction.atomic
def handle_paid_invoice(payment_request: str, amount: int):
    """
    Handle an external paid invoice:
    - Mark as paid
    - Credit user's wallet
    """
    try:
        invoice = Invoice.objects.select_for_update().get(payment_request=payment_request)
    except Invoice.DoesNotExist:
        print(f"[Invoice Handler] ⚠️ External invoice not found: {payment_request}")
        return

    if invoice.status == "paid":
        print(f"[Invoice Handler] ⚠️ Invoice already marked as paid: {payment_request}")
        return

    # Mark invoice as paid
    invoice.status = "paid"
    invoice.paid_at = timezone.now()
    invoice.save()
    print(f"[Invoice Handler] ✅ External invoice {invoice.id} marked as paid")

    # Credit user's wallet
    wallet = invoice.wallet
    wallet.add_balance(amount)
    print(f"[Invoice Handler] 💰 Credited {amount} sats to {wallet.user.username}")
