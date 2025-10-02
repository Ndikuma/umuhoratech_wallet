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
            "note", "btc_address","direction","payout_data", "btc_amount", "btc_txid", "created_at"
        ]
        read_only_fields = ["fee", "total_amount", "status", "btc_amount", "btc_address", "btc_txid"]

    def create(self, validated_data):
        user = self.context["request"].user
        print(self.context["request"].data)
        provider = validated_data.pop("provider")
        amount = validated_data["amount"]
        direction = validated_data.get("direction", "buy")
        btc_amount = self.context["request"].data.get("btc_amount")
        print(btc_amount)
        wallet = Wallet.objects.get(user=user)

        # Calculate fee
        fee = provider.calculate_fee(amount)

        # Calculate total_amount differently based on direction
        if direction == "buy":
            total_amount = amount + fee
        elif direction == "sell":
            total_amount = amount - fee
        else:
            total_amount = amount  # fallback

        order_kwargs = dict(
            user=user,
            provider=provider,
            fee=fee,
            total_amount=total_amount,
            btc_amount=btc_amount,
            **validated_data,
        )

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

            # Use service wallet
            service_wallet = Wallet.objects.filter(is_service=True).first()
            if not service_wallet:
                raise serializers.ValidationError("Service wallet not configured.")
            if not service_wallet.bitcoin_address:
                service_wallet.generate_new_address()
            order_kwargs["btc_address"] = service_wallet.bitcoin_address
            # try:
            #     tx_id=wallet.send_transaction(service_wallet.bitcoin_address, btc_amount)
            #     order_kwargs["btc_txid"] = tx_id["txid"]
            # except Exception as e:
            #     raise serializers.ValidationError(str(e))
        else:
            raise serializers.ValidationError({"direction": "Invalid direction."})


        order = Order.objects.create(**order_kwargs)
        return order

class CalculateFeeSerializer(serializers.Serializer):
    provider_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=18, decimal_places=8)
    currency=serializers.CharField(max_length=10, default="USD")