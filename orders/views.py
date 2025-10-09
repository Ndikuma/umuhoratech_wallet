from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Provider, Order
from .serializers import ProviderSerializer, OrderSerializer, CalculateFeeSerializer
from rest_framework.views import APIView
from rest_framework import status
from decimal import Decimal
import requests




class ProviderViewSet(viewsets.ReadOnlyModelViewSet):
    """
    View providers that can be used for buying or selling BTC
    """
    queryset = Provider.objects.filter(is_active=True)
    serializer_class = ProviderSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    @action(detail=False, methods=["get"])
    def buy(self, request):
        providers = self.queryset.filter(can_buy=True)
        serializer = self.get_serializer(providers, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def sell(self, request):
        providers = self.queryset.filter(can_sell=True)
        serializer = self.get_serializer(providers, many=True)
        return Response(serializer.data)


class OrderViewSet(viewsets.ModelViewSet):
    """
    A viewset that handles creating, listing, retrieving, and updating Orders.
    Supports both On-Chain and Lightning payments.
    """
    queryset = Order.objects.all().select_related('user', 'provider')
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Optionally filter by current user only
        return self.queryset.filter(user=user).order_by('-created_at')

    def perform_create(self, serializer):
        print(self.request.data)
        # Pass request context so serializer can access user and extra fields
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'])
    def lightning(self, request):
        """
        Optional: Filter only lightning orders
        """
        lightning_orders = self.get_queryset().filter(payment_method='lightning')
        serializer = self.get_serializer(lightning_orders, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def on_chain(self, request):
        """
        Optional: Filter only on-chain orders
        """
        on_chain_orders = self.get_queryset().filter(payment_method='on_chain')
        serializer = self.get_serializer(on_chain_orders, many=True)
        return Response(serializer.data)



def convert_fiat_to_btc(amount: Decimal, currency: str) -> Decimal:
    """
    Convert fiat to BTC.
    - If USD, convert directly to BTC.
    - If BIF, convert BIF -> USD -> BTC.
    Returns BTC as Decimal.
    """
    try:
        if currency.upper() == "USD":
            url = f"https://api.yadio.io/convert/{amount}/USD/BTC"
            btc_amount = requests.get(url).json().get("result", 0)
        elif currency.upper() == "BIF":
            # Step 1: BIF -> USD
            url_usd = f"https://api.yadio.io/convert/{amount}/BIF/USD"
            usd_amount = requests.get(url_usd).json().get("result", 0)
            # Step 2: USD -> BTC
            url_btc = f"https://api.yadio.io/convert/{usd_amount}/USD/BTC"
            btc_amount = requests.get(url_btc).json().get("result", 0)
        else:
            btc_amount = 0
        return Decimal(str(btc_amount))
    except Exception:
        return Decimal("0")

from decimal import Decimal, ROUND_DOWN

def convert_btc_to_sats(btc_amount):
    """
    Convert BTC to satoshis (1 BTC = 100,000,000 sats)
    Returns Decimal for precision.
    """
    if btc_amount is None:
        return Decimal("0")

    # Ensure btc_amount is a Decimal
    btc = Decimal(str(btc_amount))
    sats = (btc * Decimal("100000000")).quantize(Decimal("1"), rounding=ROUND_DOWN)
    return sats
class CalculateFeeView(APIView):
    def post(self, request):
        print(request.data)
        serializer = CalculateFeeSerializer(data=request.data)
        if serializer.is_valid():
            provider_id = serializer.validated_data["provider_id"]
            amount = Decimal(serializer.validated_data["amount"])
            currency = serializer.validated_data.get("currency", "USD")
            payment_method = serializer.validated_data.get("payment_method", "on_chain")

            try:
                provider = Provider.objects.get(id=provider_id, is_active=True)
            except Provider.DoesNotExist:
                return Response(
                    {"error": "Provider not found or inactive."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Calculate fee and total
            fee = provider.calculate_fee(amount)
            total = (amount + fee).quantize(Decimal("0.01"))

            # Convert fiat to BTC and sats
            btc_amount = convert_fiat_to_btc(amount, currency)
            sats_amount = convert_btc_to_sats(btc_amount)

            return Response({
                "amount": str(amount),
                "fee": str(fee),
                "total_amount": str(total),
                "currency": currency,
                "btc_amount": str(btc_amount),
                "sats_amount": str(sats_amount),
                "payment_method": payment_method,
            })

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)