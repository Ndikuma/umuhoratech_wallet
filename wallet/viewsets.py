"""
Professional ViewSets for Bitcoin Mini Wallet API.
"""

import logging
from decimal import Decimal
from typing import Dict, Any
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from .models import Wallet, Transaction
from .serializers import (
    UserSerializer, UserRegistrationSerializer, WalletSerializer,
    TransactionSerializer, SendTransactionSerializer, WalletBalanceSerializer,
    AddressGenerationSerializer, TransactionSyncSerializer, WalletStatsSerializer,
    LoginSerializer, PasswordChangeSerializer
)
from .permissions import (
    IsWalletOwner, IsActiveUser, HasActiveWallet, CanSendTransactions
)
from .utils import (
    create_success_response, create_error_response, log_wallet_activity,
    BitcoinRPCError, InsufficientFundsError, InvalidAddressError
)

logger = logging.getLogger('wallet')


class AuthViewSet(viewsets.GenericViewSet):
    """
    ViewSet for authentication operations.
    """
    permission_classes = [permissions.AllowAny]
    
    def get_serializer_class(self):
        if self.action == 'register':
            return UserRegistrationSerializer
        elif self.action == 'login':
            return LoginSerializer
        return UserSerializer 
    
    @extend_schema(
        operation_id='auth_register',
        summary='Register new user',
        description='Register a new user and create associated Bitcoin wallet',
        request=UserRegistrationSerializer,
        responses={201: UserSerializer}
    )
    @action(detail=False, methods=['post'])
    def register(self, request: Request) -> Response:
        """Register a new user and create wallet."""
        serializer = UserRegistrationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Registration failed",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                user = serializer.save()
                token, _ = Token.objects.get_or_create(user=user)
                
                log_wallet_activity(user, 'user_registered')
                
                return Response(
                    create_success_response({
                        'user': UserSerializer(user).data,
                        'wallet': WalletSerializer(user.wallet).data,
                        'token': token.key
                    }, "Registration successful! Your wallet has been created."),
                    status=status.HTTP_201_CREATED
                )
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return Response(
                create_error_response("Registration failed. Please try again."),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        operation_id='auth_login',
        summary='User login',
        description='Authenticate user and return access token',
        request=LoginSerializer,
        responses={200: UserSerializer}
    )
    @action(detail=False, methods=['post'])
    def login(self, request: Request) -> Response:
        """Authenticate user and return token."""
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Invalid input",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        
        if not user:
            return Response(
                create_error_response("Invalid username or password"),
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                create_error_response("Account is inactive"),
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        token, _ = Token.objects.get_or_create(user=user)
        wallet, _ = Wallet.objects.get_or_create(user=user)
        
        log_wallet_activity(user, 'user_login')
        
        return Response(
            create_success_response({
                'user': UserSerializer(user).data,
                'wallet': WalletSerializer(wallet).data,
                'token': token.key
            }, "Login successful"),
            status=status.HTTP_200_OK
        )
    
    @extend_schema(
        operation_id='auth_logout',
        summary='User logout',
        description='Logout user and invalidate token',
        responses={200: dict}
    )
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request: Request) -> Response:
        """Logout user and delete token."""
        try:
            request.user.auth_token.delete()
            log_wallet_activity(request.user, 'user_logout')
            
            return Response(
                create_success_response(message="Successfully logged out"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return Response(
                create_error_response("Error logging out"),
                status=status.HTTP_400_BAD_REQUEST
            )


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for user operations.
    """
    
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsActiveUser]
    
    def get_queryset(self):
        """Return only the current user."""
        return User.objects.filter(id=self.request.user.id)
    
    @extend_schema(
        operation_id='user_profile',
        summary='Get user profile',
        description='Get current user profile information',
        responses={200: UserSerializer}
    )
    @action(detail=False, methods=['get'])
    def profile(self, request: Request) -> Response:
        """Get current user profile."""
        return Response(
            create_success_response(
                UserSerializer(request.user).data,
                "Profile retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )
    
    @extend_schema(
        operation_id='user_change_password',
        summary='Change password',
        description='Change user password',
        request=PasswordChangeSerializer,
        responses={200: dict}
    )
    @action(detail=False, methods=['post'])
    def change_password(self, request: Request) -> Response:
        """Change user password."""
        serializer = PasswordChangeSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Invalid input",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        
        if not user.check_password(serializer.validated_data['old_password']):
            return Response(
                create_error_response("Current password is incorrect"),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        log_wallet_activity(user, 'password_changed')
        
        return Response(
            create_success_response(message="Password changed successfully"),
            status=status.HTTP_200_OK
        )


class WalletViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for wallet operations.
    """
    
    queryset = Wallet.objects.all()
    serializer_class = WalletSerializer
    permission_classes = [permissions.IsAuthenticated, IsActiveUser, HasActiveWallet, IsWalletOwner]
    
    def get_queryset(self):
        """Return only the current user's wallet."""
        return Wallet.objects.filter(user=self.request.user)
    
    def get_object(self):
        """Get the current user's wallet."""
        wallet, _ = Wallet.objects.get_or_create(user=self.request.user)
        return wallet
    
    @extend_schema(
        operation_id='wallet_detail',
        summary='Get wallet details',
        description='Get detailed wallet information including balance and statistics',
        responses={200: WalletSerializer}
    )
    def retrieve(self, request: Request, pk=None) -> Response:
        """Get wallet details."""
        wallet = self.get_object()
        
        return Response(
            create_success_response(
                WalletSerializer(wallet).data,
                "Wallet details retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )
    
    @extend_schema(
        operation_id='wallet_balance',
        summary='Get wallet balance',
        description='Get current wallet balance',
        responses={200: WalletBalanceSerializer}
    )
    @action(detail=False, methods=['get'])
    def balance(self, request: Request) -> Response:
        """Get wallet balance."""
        wallet = self.get_object()
        
        return Response(
            create_success_response(
                WalletBalanceSerializer(wallet).data,
                "Balance retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )
    
    @extend_schema(
        operation_id='wallet_update_balance',
        summary='Update wallet balance',
        description='Sync wallet balance with Bitcoin network',
        responses={200: WalletBalanceSerializer}
    )
    @action(detail=False, methods=['post'])
    def update_balance(self, request: Request) -> Response:
        """Update wallet balance from Bitcoin network."""
        try:
            wallet = self.get_object()
            balance = wallet.update_balance()
            
            log_wallet_activity(request.user, 'balance_updated', {
                'balance': str(balance)
            })
            
            return Response(
                create_success_response(
                    WalletBalanceSerializer(wallet).data,
                    "Balance updated successfully"
                ),
                status=status.HTTP_200_OK
            )
            
        except BitcoinRPCError as e:
            logger.error(f"Balance update error: {e}")
            return Response(
                create_error_response(f"Error updating balance: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        operation_id='wallet_generate_address',
        summary='Generate new address',
        description='Generate a new Bitcoin address for receiving funds',
        request=AddressGenerationSerializer,
        responses={200: dict}
    )
    @action(detail=False, methods=['post'])
    def generate_address(self, request: Request) -> Response:
        """Generate a new Bitcoin address."""
        serializer = AddressGenerationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Invalid input",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            wallet = self.get_object()
            label = serializer.validated_data.get('label', '')
            address = wallet.generate_new_address(label)
            
            return Response(
                create_success_response({
                    'address': address,
                    'label': label
                }, "Address generated successfully"),
                status=status.HTTP_200_OK
            )
            
        except BitcoinRPCError as e:
            logger.error(f"Address generation error: {e}")
            return Response(
                create_error_response(f"Error generating address: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        operation_id='wallet_stats',
        summary='Get wallet statistics',
        description='Get comprehensive wallet statistics',
        responses={200: WalletStatsSerializer}
    )
    @action(detail=False, methods=['get'])
    def stats(self, request: Request) -> Response:
        """Get wallet statistics."""
        wallet = self.get_object()
        stats = wallet.get_stats()
        
        return Response(
            create_success_response(
                stats,
                "Statistics retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )


class TransactionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for transaction operations.
    """
    
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated, IsActiveUser, HasActiveWallet, IsWalletOwner]
    
    def get_queryset(self):
        """Return only the current user's transactions."""
        wallet = Wallet.objects.get(user=self.request.user)
        return wallet.transactions.all().order_by('-timestamp')
    
    @extend_schema(
        operation_id='transaction_list',
        summary='List transactions',
        description='Get paginated list of user transactions',
        responses={200: TransactionSerializer(many=True)}
    )
    def list(self, request: Request) -> Response:
        """List user transactions."""
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = TransactionSerializer(page, many=True)
            return self.get_paginated_response(
                create_success_response(
                    serializer.data,
                    "Transactions retrieved successfully"
                )['data']
            )
        
        serializer = TransactionSerializer(queryset, many=True)
        return Response(
            create_success_response(
                serializer.data,
                "Transactions retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )
    
    @extend_schema(
        operation_id='transaction_send',
        summary='Send Bitcoin transaction',
        description='Send Bitcoin to specified address',
        request=SendTransactionSerializer,
        responses={201: TransactionSerializer}
    )
    @action(detail=False, methods=['post'], permission_classes=[
        permissions.IsAuthenticated, IsActiveUser, HasActiveWallet, CanSendTransactions
    ])
    def send(self, request: Request) -> Response:
        """Send Bitcoin transaction."""
        serializer = SendTransactionSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Invalid transaction data",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            wallet = Wallet.objects.get(user=request.user)
            
            address = serializer.validated_data['address']
            amount = serializer.validated_data['amount']
            comment = serializer.validated_data.get('comment', '')
            
            # Send transaction
            txid = wallet.send_transaction(address, amount, comment)
            
            # Get the created transaction
            transaction_obj = Transaction.objects.get(txid=txid)
            
            return Response(
                create_success_response(
                    TransactionSerializer(transaction_obj).data,
                    f"Transaction sent successfully! TXID: {txid}"
                ),
                status=status.HTTP_201_CREATED
            )
            
        except InsufficientFundsError as e:
            return Response(
                create_error_response(str(e)),
                status=status.HTTP_400_BAD_REQUEST
            )
        except (BitcoinRPCError, InvalidAddressError) as e:
            logger.error(f"Transaction error: {e}")
            return Response(
                create_error_response(f"Transaction failed: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            logger.error(f"Unexpected transaction error: {e}")
            return Response(
                create_error_response("Transaction failed. Please try again."),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        operation_id='transaction_sync',
        summary='Sync transactions',
        description='Sync transactions from Bitcoin network',
        request=TransactionSyncSerializer,
        responses={200: dict}
    )
    @action(detail=False, methods=['post'])
    def sync(self, request: Request) -> Response:
        """Sync transactions from Bitcoin network."""
        serializer = TransactionSyncSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                create_error_response(
                    "Invalid input",
                    serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            wallet = Wallet.objects.get(user=request.user)
            synced_count = wallet.sync_transactions()
            
            return Response(
                create_success_response({
                    'synced_count': synced_count,
                    'wallet': WalletSerializer(wallet).data
                }, f"Successfully synced {synced_count} new transactions"),
                status=status.HTTP_200_OK
            )
            
        except BitcoinRPCError as e:
            logger.error(f"Transaction sync error: {e}")
            return Response(
                create_error_response(f"Error syncing transactions: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )