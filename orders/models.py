from django.db import models
from django.contrib.auth.models import User
from decimal import Decimal

class Provider(models.Model):
    """Provider for payments"""
    FLOW_CHOICES = [
        ("direct", "Direct API"),
        ("redirect", "Redirect Page"),
        ("otp", "OTP Verification"),
    ]

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    flow_type = models.CharField(max_length=20, choices=FLOW_CHOICES, default="direct")
    image = models.ImageField(upload_to="providers/", blank=True, null=True, default="providers/default.png")
    is_active = models.BooleanField(default=True)
    internal = models.BooleanField(default=False)

    # API credentials
    api_url = models.URLField(blank=True, null=True)
    api_key = models.CharField(max_length=255, blank=True, null=True)
    api_secret = models.CharField(max_length=255, blank=True, null=True)
    callback_url = models.URLField(blank=True, null=True)
    contact_url = models.URLField(blank=True, null=True)

    # JSON fields
    payment_info = models.JSONField(default=dict, blank=True, help_text="Instructions for payment")
    extra_config = models.JSONField(default=dict, blank=True)
    currencies = models.JSONField(default=list, help_text="Supported currencies, e.g., ['BIF','USD']")
    exchange_rate_to_usd = models.DecimalField(max_digits=12, decimal_places=6, default=7500, null=True, blank=True)

    # Fees
    fee_type = models.CharField(max_length=10, choices=[("fixed", "Fixed"), ("percent", "Percentage")], default="percent")
    fee_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    # Buy/Sell flags
    can_buy = models.BooleanField(default=True)
    can_sell = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def calculate_fee(self, amount):
        if self.fee_type == "fixed":
            return self.fee_value
        elif self.fee_type == "percent":
            return (Decimal(amount) * self.fee_value / 100).quantize(Decimal("0.01"))
        return Decimal(0)


class Order(models.Model):
    """User order for buying or selling BTC"""
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("completed", "Completed"),
        ("awaiting_confirmation", "Awaiting Confirmation"),
        ("failed", "Failed"),
    ]
    DIRECTION_CHOICES = [
        ("buy", "Buy"),
        ("sell", "Sell"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders")
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE, related_name="orders")
    direction = models.CharField(max_length=10, choices=DIRECTION_CHOICES, default="buy")
    amount_currency = models.CharField(max_length=10, default="USD")
    amount = models.DecimalField(max_digits=18, decimal_places=8)
    fee = models.DecimalField(max_digits=18, decimal_places=8, default=0)
    total_amount = models.DecimalField(max_digits=18, decimal_places=8, default=0)
    # SELL-specific user payout details
    payout_data = models.JSONField(
        default=list,
        blank=True,
        help_text="Contains user account details to pay them during sell (e.g., mobile money, bank)"
    )
    payment_proof = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=200, choices=STATUS_CHOICES, default="pending")
    note = models.TextField(blank=True, null=True)

    btc_address = models.CharField(max_length=255, blank=True, null=True)
    btc_amount = models.DecimalField(max_digits=18, decimal_places=8, blank=True, null=True)
    btc_txid = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Order #{self.id} by {self.user.username}"
    def save(self, *args, **kwargs):
        """
        Override save() to automatically update status when payment proof is provided.
        """
        if self.status == "pending" and self.payment_proof:
            self.status = "awaiting_confirmation"

        super().save(*args, **kwargs)