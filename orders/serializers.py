from rest_framework import serializers
from .models import Provider, Order
from django.contrib.auth.models import User
from walletapp.models import Wallet


class ProviderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        fields = "__all__"

class OrderSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    provider = ProviderSerializer(read_only=True)
    provider_id = serializers.PrimaryKeyRelatedField(
        queryset=Provider.objects.all(), source='provider', write_only=True
    )

    class Meta:
        model = Order
        fields = [
            "id", "user", "provider", "provider_id", "amount_currency",
            "amount", "fee", "total_amount", "payment_proof", "status",
            "note", "btc_address", "direction", "payout_data",
            "btc_amount", "btc_txid",
            "ln_invoice", "ln_amount_sats", "ln_payment_hash", "ln_paid_at",
            "payment_method", "created_at"
        ]
        read_only_fields = [
            "fee", "total_amount", "status", "btc_amount", "btc_address",
            "btc_txid", "ln_invoice", "ln_amount_sats", "ln_payment_hash", "ln_paid_at"
        ]

    def create(self, validated_data):
        user = self.context["request"].user
        provider = validated_data.pop("provider")
        direction = validated_data.get("direction")
        payment_method = validated_data.get("payment_method", "on_chain")
        amount = validated_data.get("amount")
        btc_amount = self.context["request"].data.get("btc_amount")
        ln_invoice = self.context["request"].data.get("ln_invoice")
        ln_amount_sats = self.context["request"].data.get("ln_amount_sats")

        wallet = Wallet.objects.get(user=user)

        # Calculate fee
        if not amount:
            amount=0
        fee = provider.calculate_fee(amount)

        # Calculate total_amount differently based on direction
        if direction == "buy":
            total_amount = amount + fee
        elif direction == "sell":
            total_amount = amount - fee
        else:
            total_amount = amount  # fallback

        order_kwargs = dict(
            provider=provider,
            fee=fee,
            total_amount=total_amount,
            **validated_data,
        )

        # -------------------------
        # On-chain payment
        # -------------------------
        if payment_method == "on_chain":
            order_kwargs["btc_amount"] = btc_amount
            if direction == "buy":
                if not wallet.bitcoin_address:
                    wallet.generate_new_address()
                order_kwargs["btc_address"] = wallet.bitcoin_address
            elif direction == "sell":
                payout_data = validated_data.get("payout_data")
                if not payout_data:
                    raise serializers.ValidationError(
                        {"payout_data": "Payout details are required for sell orders."}
                    )
                # Use service wallet for receiving BTC
                service_wallet = Wallet.objects.filter(is_service=True).first()
                if not service_wallet:
                    raise serializers.ValidationError("Service wallet not configured.")
                if not service_wallet.bitcoin_address:
                    service_wallet.generate_new_address()
                order_kwargs["btc_address"] = service_wallet.bitcoin_address

        # -------------------------
        # Lightning payment
        # -------------------------
        elif payment_method == "lightning":
            order_kwargs["amount"]=ln_amount_sats
            order_kwargs["ln_invoice"] = ln_invoice
            order_kwargs["ln_amount_sats"] = ln_amount_sats

        else:
            raise serializers.ValidationError({"payment_method": "Invalid payment method."})

        order = Order.objects.create(**order_kwargs)
        return order

class CalculateFeeSerializer(serializers.Serializer):
    provider_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=18, decimal_places=8)
    currency=serializers.CharField(max_length=10, default="USD")

class OnChainOrderSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    provider = ProviderSerializer(read_only=True)
    provider_id = serializers.PrimaryKeyRelatedField(
        queryset=Provider.objects.all(), source='provider', write_only=True
    )

    class Meta:
        model = Order
        fields = [
            "id", "user", "provider", "provider_id", "amount_currency",
            "amount", "fee", "total_amount", "payment_proof", "status",
            "note", "btc_address", "direction", "payout_data",
            "btc_amount", "btc_txid", "payment_method", "created_at"
        ]
        read_only_fields = [
            "fee", "total_amount", "status", "btc_amount",
            "btc_address", "btc_txid"
        ]

class LightningOrderSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    provider = ProviderSerializer(read_only=True)
    provider_id = serializers.PrimaryKeyRelatedField(
        queryset=Provider.objects.all(), source='provider', write_only=True
    )

    class Meta:
        model = Order
        fields = [
            "id", "user", "provider", "provider_id", "amount_currency",
            "amount", "fee", "total_amount", "payment_proof", "status",
            "note", "direction", "payout_data",
            "ln_invoice", "ln_amount_sats", "ln_payment_hash", "ln_paid_at",
            "payment_method", "created_at"
        ]
        read_only_fields = [
            "fee", "total_amount", "status",
            "ln_invoice", "ln_amount_sats", "ln_payment_hash", "ln_paid_at"
        ]
