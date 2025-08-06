from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import transaction as db_transaction
from .models import Wallet, Transaction
from .serializers import (
    UserSerializer, UserRegistrationSerializer, WalletSerializer,
    TransactionSerializer, SendTransactionSerializer, WalletBalanceSerializer
)
from .rpc_client import get_rpc


class UserRegistrationAPIView(generics.CreateAPIView):
    """API endpoint for user registration"""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Create wallet for the user
        wallet, created = Wallet.objects.get_or_create(user=user)
        
        # Create token for authentication
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'user': UserSerializer(user).data,
            'wallet': WalletSerializer(wallet).data,
            'token': token.key,
            'message': 'Registration successful! Your wallet has been created.'
        }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_api_view(request):
    """API endpoint for user login"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({
            'error': 'Username and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=username, password=password)
    if user:
        token, created = Token.objects.get_or_create(user=user)
        wallet, created = Wallet.objects.get_or_create(user=user)
        
        return Response({
            'user': UserSerializer(user).data,
            'wallet': WalletSerializer(wallet).data,
            'token': token.key,
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Invalid username or password'
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_api_view(request):
    """API endpoint for user logout"""
    try:
        request.user.auth_token.delete()
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)
    except:
        return Response({
            'error': 'Error logging out'
        }, status=status.HTTP_400_BAD_REQUEST)


class WalletDetailAPIView(generics.RetrieveAPIView):
    """API endpoint to get wallet details"""
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        wallet, created = Wallet.objects.get_or_create(user=self.request.user)
        return wallet


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_wallet_balance(request):
    """API endpoint to update wallet balance"""
    try:
        wallet, created = Wallet.objects.get_or_create(user=request.user)
        balance = wallet.update_balance()
        
        return Response({
            'balance': balance,
            'message': 'Balance updated successfully'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': f'Error updating balance: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TransactionListAPIView(generics.ListAPIView):
    """API endpoint to list user's transactions"""
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        wallet, created = Wallet.objects.get_or_create(user=self.request.user)
        return wallet.transactions.order_by('-timestamp')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_transaction_api_view(request):
    """API endpoint to send Bitcoin transaction"""
    serializer = SendTransactionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    wallet, created = Wallet.objects.get_or_create(user=request.user)
    wallet.update_balance()
    
    address = serializer.validated_data['address']
    amount = serializer.validated_data['amount']
    
    if amount > wallet.balance:
        return Response({
            'error': 'Insufficient balance'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        with db_transaction.atomic():
            rpc = get_rpc(wallet.user.username)
            rpc.settxfee(0.00001)
            txid = rpc.sendtoaddress(address, float(amount))
            
            if txid:
                # Create transaction record
                transaction = Transaction.objects.create(
                    wallet=wallet,
                    txid=txid,
                    amount=-amount,  # Negative for sent transactions
                    transaction_type='send',
                    address=address,
                    confirmations=0,
                    timestamp=timezone.now(),
                )
                
                # Update wallet balance
                wallet.update_balance()
                
                return Response({
                    'transaction': TransactionSerializer(transaction).data,
                    'wallet': WalletSerializer(wallet).data,
                    'message': f'Transaction successful! TXID: {txid}'
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'error': 'Transaction failed. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
    except Exception as e:
        return Response({
            'error': f'Transaction error: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def wallet_dashboard_api_view(request):
    """API endpoint for wallet dashboard data"""
    wallet, created = Wallet.objects.get_or_create(user=request.user)
    recent_transactions = wallet.transactions.order_by('-timestamp')[:5]
    
    return Response({
        'wallet': WalletSerializer(wallet).data,
        'recent_transactions': TransactionSerializer(recent_transactions, many=True).data,
        'total_transactions': wallet.transactions.count(),
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def sync_transactions_api_view(request):
    """API endpoint to sync transactions from Bitcoin RPC"""
    try:
        wallet, created = Wallet.objects.get_or_create(user=request.user)
        rpc = get_rpc(wallet.user.username)
        transactions = rpc.listtransactions("*", 20)
        
        synced_count = 0
        for tx in transactions:
            transaction, created = Transaction.objects.get_or_create(
                txid=tx['txid'],
                defaults={
                    'wallet': wallet,
                    'amount': tx['amount'],
                    'transaction_type': 'receive' if tx['amount'] > 0 else 'send',
                    'address': tx.get('address', ''),
                    'confirmations': tx.get('confirmations', 0),
                    'timestamp': timezone.datetime.fromtimestamp(tx['time'], tz=timezone.utc),
                }
            )
            if created:
                synced_count += 1
        
        # Update wallet balance after sync
        wallet.update_balance()
        
        return Response({
            'message': f'Successfully synced {synced_count} new transactions',
            'wallet': WalletSerializer(wallet).data,
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'Error syncing transactions: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_api_view(request):
    """API endpoint to get user profile"""
    return Response({
        'user': UserSerializer(request.user).data
    }, status=status.HTTP_200_OK)