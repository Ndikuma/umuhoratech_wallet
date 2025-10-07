from django.db import models, transaction
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone

User = get_user_model()


class WalletLocal(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="walletlocal")
    balance = models.BigIntegerField(default=0)  # in sats
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.balance} sats"

    @transaction.atomic
    def add_balance(self, amount: int):
        """Add sats to wallet balance"""
        if amount <= 0:
            raise ValidationError("Amount to add must be positive.")
        self.balance += amount
        self.save()
        return self.balance

    @transaction.atomic
    def subtract_balance(self, amount: int):
        """Subtract sats from wallet balance"""
        if amount <= 0:
            raise ValidationError("Amount to subtract must be positive.")
        if self.balance < amount:
            raise ValidationError("Insufficient balance.")
        self.balance -= amount
        self.save()
        return self.balance
     # ------------------- Wallet Stats -------------------
    @property
    def total_invoices(self):
        return self.invoices.count()

    @property
    def total_paid_invoices(self):
        return self.invoices.filter(status="paid").count()

    @property
    def total_pending_invoices(self):
        return self.invoices.filter(status="pending").count()

    @property
    def total_expired_invoices(self):
        return self.invoices.filter(status="expired").count()

    @property
    def total_received_sats(self):
        """Total sats received (sum of paid incoming invoices)"""
        return self.invoices.filter(status="paid", is_outgoing=False).aggregate(
            total=models.Sum("amount")
        )["total"] or 0

    @property
    def total_sent_sats(self):
        """Total sats sent (sum of paid outgoing invoices)"""
        return self.invoices.filter(status="paid", is_outgoing=True).aggregate(
            total=models.Sum("amount")
        )["total"] or 0

    @property
    def invoice_summary(self):
        """Convenient dictionary with stats"""
        return {
            "balance": self.balance,
            "total_invoices": self.total_invoices,
            "paid_invoices": self.total_paid_invoices,
            "pending_invoices": self.total_pending_invoices,
            "expired_invoices": self.total_expired_invoices,
            "total_received_sats": self.total_received_sats,
            "total_sent_sats": self.total_sent_sats,
        }
   

class Invoice(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("paid", "Paid"),
        ("expired", "Expired"),
    ]

    wallet = models.ForeignKey("WalletLocal", on_delete=models.CASCADE, related_name="invoices")
    payment_request = models.TextField()  # bolt11 string
    payment_hash = models.TextField(null=True,blank=True)
    amount = models.BigIntegerField(blank=True, null=True)  # sats
    memo = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    is_outgoing = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    paid_at = models.DateTimeField(blank=True, null=True)
    qr_code = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Invoice {self.id} - {self.amount or '?'} sats ({self.status})"

    def mark_paid(self):
        """Mark invoice as paid and set paid_at timestamp"""
        self.status = "paid"
        self.paid_at = timezone.now()
        self.save()

    def mark_expired(self):
        """Mark invoice as expired"""
        self.status = "expired"
        self.save()