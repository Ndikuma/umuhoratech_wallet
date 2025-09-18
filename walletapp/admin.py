from django.contrib import admin
from .models import Wallet, Transaction

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "wallet_name",
        "bitcoin_address",
        "network",
        "balance",
        "created_at",
        "updated_at",
    )
    list_filter = ("network",)
    search_fields = ("user__username", "wallet_name", "bitcoin_address")
    readonly_fields = ("balance", "created_at", "updated_at")
    ordering = ("-created_at",)

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "txid",
        "wallet",
        "transaction_type",
        "amount",
        "fee",
        "service_fee",
        "from_address",
        "to_address",
        "status",
        "confirmations",
        "created_at",
    )
    list_filter = ("transaction_type", "status")
    search_fields = ("txid", "from_address", "to_address")
    readonly_fields = (
        "txid",
        "wallet",
        "amount",
        "fee",
        "service_fee",
        "from_address",
        "to_address",
        "status",
        "confirmations",
        "raw_tx",
        "tx_size_bytes",
        "explorer_url",
        "created_at",
        "updated_at",
    )
    ordering = ("-created_at",)
