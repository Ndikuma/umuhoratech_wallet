from django.db import models, transaction
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone


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


class Invoice(models.Model):
    STATUS_CHOICES = [
        ("UNPAID", "Unpaid"),
        ("PAID", "Paid"),
        ("CANCELLED", "Cancelled"),
        ("EXPIRED", "Expired"),
    ]

    wallet = models.ForeignKey(WalletLocal, on_delete=models.CASCADE, related_name="invoices")
    payment_request = models.TextField(unique=True)  # bolt11 string
    amount = models.BigIntegerField(blank=True, null=True)  # sats
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="UNPAID")
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"Invoice {self.id} - {self.amount or '?'} sats ({self.status})"

    def mark_paid(self):
        """Mark invoice as paid and set paid_at timestamp"""
        self.status = "PAID"
        self.paid_at = timezone.now()
        self.save()

    def mark_unpaid(self):
        """Mark invoice as unpaid"""
        self.status = "UNPAID"
        self.paid_at = None
        self.save()

    def mark_cancelled(self):
        """Mark invoice as cancelled"""
        self.status = "CANCELLED"
        self.paid_at = None
        self.save()