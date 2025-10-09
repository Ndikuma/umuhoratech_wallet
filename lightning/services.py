from django.utils import timezone
from django.db import transaction
from .models import WalletLocal, Invoice
from .blink_wallet import BlinkWallet


class BlinkWalletService:
    def __init__(self, user):
        self.user = user
        self.client = BlinkWallet("blink_bPc4Pm67gHpIElVjxgAgSEMuSmOntM0o8tPWOMSzeme8wpMvG8mT1GSb03UziTTy")  # uses BLINK_API_KEY
        self.wallet_local, _ = WalletLocal.objects.get_or_create(user=user)

    @transaction.atomic
    def create_invoice(self, amount: int, memo: str = None, ) -> Invoice:
        """
        Create Lightning invoice via Blink and store all fields locally.
        """
        # Call Blink API
        remote_invoice = self.client.create_ln_invoice(amount)

        payment_request = remote_invoice.get("paymentRequest")
        payment_hash = remote_invoice.get("paymentHash")
        satoshis = remote_invoice.get("satoshis", amount)

        # Optional memo
        memo_text = memo or ""

        # QR code
        qr_code_data = self.client.generate_qr(payment_request)

        # expires_at (optional, not provided by Blink currently)
        expires_at = None
        if "expires_at" in remote_invoice:
            expires_at = remote_invoice["expires_at"]

        # Save invoice locally
        invoice = Invoice.objects.create(
            wallet=self.wallet_local,
            payment_request=payment_request,
            payment_hash=payment_hash,
            amount=satoshis,
            memo=memo_text,
            status="pending",
            is_outgoing=False,
            expires_at=expires_at,
            qr_code=qr_code_data,
        )

        return invoice

    @transaction.atomic
    def pay_invoice(self, payment_request: str, amount: int = None):
        """
        Pay an invoice:
        - If internal: transfer sats, mark invoice as paid, create mirror outgoing invoice.
        - If external: pay via Blink, create mirror outgoing invoice.
        """
        try:
            invoice = Invoice.objects.select_for_update().get(payment_request=payment_request)
            internal = True
        except Invoice.DoesNotExist:
            invoice = None
            internal = False

        # --- Internal Payment ---
        if internal:
            if invoice.status != "pending":
                return {"status": "FAILED", "error": "Invoice already processed"}

            if self.wallet_local.balance < invoice.amount:
                return {"status": "FAILED", "error": "Insufficient balance"}

            # Move sats
            self.wallet_local.subtract_balance(invoice.amount)
            invoice.wallet.add_balance(invoice.amount)

            # Mark invoice as paid
            invoice.mark_paid()

            # Create outgoing mirror invoice for payer
            mirror = Invoice.objects.create(
                wallet=self.wallet_local,
                payment_request=invoice.payment_request,
                payment_hash=invoice.payment_hash,
                amount=invoice.amount,
                memo=invoice.memo,
                status="paid",
                is_outgoing=True,
                created_at=invoice.created_at,
                paid_at=invoice.paid_at
            )

            return {
                "status": "SUCCESS",
                "type": "internal",
                "from": self.wallet_local.user.username,
                "to": invoice.wallet.user.username,
                "amount": invoice.amount,
                "incoming_invoice_id": invoice.id,
                "outgoing_invoice_id": mirror.id,
            }

        # --- External Payment ---
        # Send via Blink
        payment = self.client.pay_ln_invoice(payment_request, amount)
        payment_amount = None
        if "payment" in payment:
            try:
                msg = payment.get("check", "")
                if "sats" in msg:
                    payment_amount = int(msg.split()[-2])
            except Exception:
                payment_amount = amount

        # Subtract from payer balance
        self.wallet_local.subtract_balance(amount)

        # Create mirror outgoing invoice
        mirror = Invoice.objects.create(
            wallet=self.wallet_local,
            payment_request=payment_request,
            payment_hash=None,
            amount=payment_amount,
            memo=None,
            status="paid",
            is_outgoing=True,
            paid_at=timezone.now()
        )

        return {
            "status": "SUCCESS",
            "type": "external",
            "amount": payment_amount,
            "outgoing_invoice_id": mirror.id,
            "response": payment,
        }

    # -------------------------
    # LN Address Payment
    # -------------------------
    @transaction.atomic
    def pay_ln_address(self, ln_address: str, amount: int):
        """
        Send BTC to a Lightning Address (external only)
        """
        payment = self.client.pay_ln_address(ln_address, amount)
        self.wallet_local.subtract_balance(amount)
        invoice = Invoice.objects.create(
            wallet=self.wallet_local,
            payment_request=ln_address,
            amount=amount,
            status="paid"
        )
        invoice.mark_paid()
        return {
            "status": payment.get("status"),
            "type": "ln_address",
            "response": payment,
        }

    # -------------------------
    # LNURL Payment
    # -------------------------
    @transaction.atomic
    def pay_lnurl(self, lnurl: str, amount: int):
        """
        Send BTC to a static LNURL payRequest (external only)
        """
        payment = self.client.pay_lnurl(lnurl, amount)
        self.wallet_local.subtract_balance(amount)
        invoice = Invoice.objects.create(
            wallet=self.wallet_local,
            payment_request=lnurl,
            amount=amount,
            status="paid"   
        )
        invoice.mark_paid()
        return {
            "status": payment.get("status"),
            "type": "lnurl",
            "response": payment,
        }
    
    @transaction.atomic
    def credit_external_invoice(self, invoice_data):
        """
        Called when Blink WS reports an invoice as paid.
        """
        payment_request = invoice_data.get("paymentRequest")
        amount = invoice_data.get("amount", 0)
        status = invoice_data.get("status", "paid")

        invoice, created = Invoice.objects.get_or_create(
            payment_request=payment_request,
            defaults={
                "wallet": self.wallet_local,
                "amount": amount,
                "status": status,
                "paid_at": timezone.now(),
            },
        )

        if not created and invoice.status != "paid":
            invoice.status = "paid"
            invoice.paid_at = timezone.now()
            invoice.save()

        # Update user wallet balance
        self.wallet_local.add_balance(amount)
        print(f"[Blink Wallet] ✅ Credited {amount} sats to {self.user.username}")