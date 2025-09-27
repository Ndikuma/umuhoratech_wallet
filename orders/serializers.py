from rest_framework import serializers
from .models import Provider, Order
from django.contrib.auth.models import User

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
        user = self.context['request'].user
        provider = validated_data.pop('provider')
        amount = validated_data['amount']

        # Calculate fee and total
        fee = provider.calculate_fee(amount)
        total_amount = amount + fee

        order = Order.objects.create(
            user=user,
            provider=provider,
            fee=fee,
            total_amount=total_amount,
            **validated_data
        )
        return order
class CalculateFeeSerializer(serializers.Serializer):
    provider_id = serializers.IntegerField()
    amount = serializers.DecimalField(max_digits=18, decimal_places=8)
    currency=serializers.CharField(max_length=10, default="USD")