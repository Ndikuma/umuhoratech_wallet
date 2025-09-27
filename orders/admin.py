from django.contrib import admin
from .models import Provider, Order


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "is_active",
        "internal",
        "can_buy",
        "can_sell",
        "fee_type",
        "fee_value",
        "exchange_rate_to_usd",
        "created_at",
    )
    list_filter = ("is_active", "can_buy", "can_sell", "fee_type")
    search_fields = ("name", "description")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (None, {
            "fields": ("name", "description", "image", "is_active", "internal")
        }),
        ("Flow Settings", {
            "fields": ("flow_type",)
        }),
        ("API Config", {
            "fields": ("api_url", "api_key", "api_secret", "callback_url", "contact_url"),
            "classes": ("collapse",),
        }),
        ("Payment & Currency", {
            "fields": ("payment_info", "currencies", "exchange_rate_to_usd", "extra_config"),
        }),
        ("Fees & Options", {
            "fields": ("fee_type", "fee_value", "can_buy", "can_sell"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "provider",
        "direction",
        "amount",
        "fee",
        "total_amount",
        "status",
        "created_at",
    )
    list_filter = ("status", "direction", "amount_currency", "provider")
    search_fields = ("user__username", "btc_address", "btc_txid", "note")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (None, {
            "fields": ("user", "provider", "direction", "status", "note")
        }),
        ("Amounts", {
            "fields": ("amount_currency", "amount", "fee", "total_amount"),
        }),
        ("BTC Details", {
            "fields": ("btc_address", "btc_amount", "btc_txid"),
        }),
        ("Payment Proof & Payout", {
            "fields": ("payment_proof", "payout_data"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )
