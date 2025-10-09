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
from .serializers import *
from .permissions import (
    IsWalletOwner, IsActiveUser, HasActiveWallet, CanSendTransactions
)
from .utils import *

logger = logging.getLogger('wallet')

from rest_framework import status, permissions, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django_otp.plugins.otp_email.models import EmailDevice
from rest_framework.authtoken.models import Token
from django.db.models import Q

from .serializers import (
    UserRegistrationSerializer,
    LoginSerializer,
    VerifyOTPSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
)
from .utils import create_success_response, create_error_response

import logging
logger = logging.getLogger(__name__)

User = get_user_model()


class AuthViewSet(viewsets.GenericViewSet):
    """Unified Authentication ViewSet using DRF TokenAuth and Email OTP."""
    permission_classes = [permissions.AllowAny]
    queryset = User.objects.all()

    def get_serializer_class(self):
        if self.action == "register":
            return UserRegistrationSerializer
        elif self.action == "login":
            return LoginSerializer
        elif self.action == "verify_email":
            return VerifyOTPSerializer
        elif self.action == "change_password":
            return PasswordChangeSerializer
        elif self.action == "reset_password":
            return PasswordResetSerializer
        elif self.action == "confirm_reset":
            return PasswordResetConfirmSerializer
        elif self.action == "verify_security_otp":
            return VerifyOTPSerializer
        return None

    # ------------------- Register -------------------
    @action(detail=False, methods=["post"])
    def register(self, request):
        """Register new user and send email OTP."""
        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        if  User.objects.filter(Q(email=email) | Q(username=email)).first():
            return Response(create_error_response("Email already exists."),
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                user = serializer.save(is_active=False, is_email_verified=False)
                device, _ = EmailDevice.objects.get_or_create(user=user)
                # device.generate_challenge()  # sends OTP

                return Response(create_success_response({
                    "email": user.email,
                    "message": "Account created. OTP sent to your email."
                }), status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return Response(create_error_response("Registration failed."),
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ------------------- Verify Email -------------------
    @action(detail=False, methods=["post"])
    def verify_email(self, request):
        """Verify OTP to activate account."""
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        user = User.objects.filter(Q(email=email) | Q(username=email)).first()
        if not user:
            return Response(create_error_response("User not found."),
                            status=status.HTTP_404_NOT_FOUND)

        device = EmailDevice.objects.filter(user=user).first()
        if not device or not device.verify_token(otp):
            return Response(create_error_response("Invalid or expired OTP."),
                            status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.is_email_verified = True
        user.save()

        token, _ = Token.objects.get_or_create(user=user)
        return Response(create_success_response({
            "user_id": user.id,
            "email": user.email,
            "token": token.key,
            "message": "Email verified successfully."
        }), status=status.HTTP_200_OK)

    # ------------------- Login -------------------
    @action(detail=False, methods=["post"])
    def login(self, request):
        """Authenticate user using email or username."""
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                create_error_response(serializer.errors),
                status=status.HTTP_400_BAD_REQUEST
            )

        identifier = serializer.validated_data["identifier"]
        password = serializer.validated_data["password"]

        user = authenticate(username=identifier, password=password)
        if not user:
            return Response(
                create_error_response("Invalid credentials."),
                status=status.HTTP_401_UNAUTHORIZED
            )

        # if not user.is_email_verified:
        #     return Response(
        #         create_error_response("Email not verified."),
        #         status=status.HTTP_403_FORBIDDEN
        #     )

        token, _ = Token.objects.get_or_create(user=user)

        # Example: determine wallet_created

        wallet_created = hasattr(user, "wallet")  # if user has a related Wallet model
        if not wallet_created:
            wallet_created=Wallet.create_wallet_for_user(user)

        # Include tfa_required for OTP
        tfa_required = user.is_otp_required  # from your User model

        return Response(
            create_success_response({
                "token": token.key,
                "tfa_required": tfa_required,
                "wallet_created": wallet_created,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
                "message": "Login successful."
            }),
            status=status.HTTP_200_OK
        )
    # ------------------- Resend OTP -------------------
    @action(detail=False, methods=["post"])
    def resend_otp(self, request):
        print(request.data)
        """Resend verification OTP."""
        email = request.data.get("email")
        user = User.objects.filter(Q(email=email) | Q(username=email)).first()
        
        if not user:
            return Response(create_error_response("User not found."),
                            status=status.HTTP_404_NOT_FOUND)

        # if user.is_email_verified:
        #     return Response(create_error_response("Email already verified."),
        #                     status=status.HTTP_400_BAD_REQUEST)

        device, _ = EmailDevice.objects.get_or_create(user=user)
        device.generate_challenge()
        return Response(create_success_response({"message": "OTP resent to your email."}),
                        status=status.HTTP_200_OK)

    # ------------------- Change Password -------------------
    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        """Allow authenticated users to change password."""
        serializer = PasswordChangeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        current = serializer.validated_data["current_password"]
        new = serializer.validated_data["new_password"]

        user = request.user
        if not user.check_password(current):
            return Response(create_error_response("Current password is incorrect."),
                            status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new)
        user.save()
        return Response(create_success_response({"message": "Password changed successfully."}),
                        status=status.HTTP_200_OK)

    # ------------------- Reset Password (Send OTP) -------------------
    @action(detail=False, methods=["post"])
    def reset_password(self, request):
        """Send OTP for password reset."""
        serializer = PasswordResetSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        user = User.objects.filter(Q(email=email) | Q(username=email)).first()
        
        if not user:
            return Response(create_error_response("User not found."),
                            status=status.HTTP_404_NOT_FOUND)

        device, _ = EmailDevice.objects.get_or_create(user=user)
        device.generate_challenge()
        return Response(create_success_response({"message": "Reset OTP sent to your email."}),
                        status=status.HTTP_200_OK)

    # ------------------- Confirm Password Reset -------------------
    @action(detail=False, methods=["post"])
    def confirm_reset(self, request):
        """Confirm OTP and set new password."""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        new_password = serializer.validated_data["password"]

        user = User.objects.filter(Q(email=email) | Q(username=email)).first()
        
        if not user:
            return Response(create_error_response("User not found."),
                            status=status.HTTP_404_NOT_FOUND)

        device = EmailDevice.objects.filter(user=user).first()
        if not device or not device.verify_token(otp):
            return Response(create_error_response("Invalid OTP."),
                            status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response(create_success_response({"message": "Password reset successfully."}),
                        status=status.HTTP_200_OK)

    # ------------------- Verify OTP for Security -------------------
    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def verify_security_otp(self, request):
        """Verify OTP for sensitive operations (security layer)."""
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(create_error_response(serializer.errors),
                            status=status.HTTP_400_BAD_REQUEST)

        otp = serializer.validated_data["otp"]
        device = EmailDevice.objects.filter(user=request.user).first()
        if not device or not device.verify_token(otp):
            return Response(create_error_response("Invalid OTP."),
                            status=status.HTTP_400_BAD_REQUEST)

        return Response(create_success_response({"message": "OTP verified successfully."}),
                        status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request):
        """Log out user by deleting their auth token."""
        try:
            # Delete the token associated with the authenticated user
            Token.objects.filter(user=request.user).delete()
            return Response(
                create_success_response({"message": "Logged out successfully."}),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                create_error_response(f"Logout failed: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for user operations."""
    
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsActiveUser]
    
    def get_queryset(self):
        """Return only the current user."""
        return User.objects.filter(id=self.request.user.id)
    
    @action(detail=False, methods=["get"])
    def me(self, request):
        """Return authenticated user with full data as a dict."""
        user = request.user

        data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_email_verified": user.is_email_verified,
            "tfa_required": getattr(user, "is_otp_required", False),
            "wallet_created": hasattr(user, "wallet"),  # True if user has a related wallet

        }

        return Response(data, status=status.HTTP_200_OK)

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

class WalletViewSet(viewsets.ModelViewSet):
    """ViewSet for wallet operations."""

    queryset = Wallet.objects.all()
    serializer_class = WalletSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Return only the current user's wallet."""
        return Wallet.objects.filter(user=self.request.user)

    def get_wallet(self):
        """Fetch the user's wallet or raise error if none exists."""
        try:
            return Wallet.objects.get(user=self.request.user)
        except Wallet.DoesNotExist:
            raise NotFound(detail="Wallet not found for this user.")

    @extend_schema(
        operation_id='wallet_generate_mnemonic',
        summary='Generate mnemonic phrase',
        description='Generate a BIP39 mnemonic phrase with specified word count and language',
        request=GenerateMnemonicSerializer,
        responses={200: GenerateMnemonicSerializer}
    )
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsActiveUser])
    def generate_mnemonic(self, request):
        serializer = GenerateMnemonicSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                create_error_response("Invalid input", serializer.errors),
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            result = serializer.save()
            log_wallet_activity(request.user, 'mnemonic_generated', {
                'word_count': result['word_count'],
                'language': result['language']
            })
            return Response(
                create_success_response(result, "Mnemonic phrase generated successfully"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Mnemonic generation error: {e}")
            return Response(
                create_error_response("Failed to generate mnemonic phrase"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        operation_id="wallet_create",
        summary="Create a new wallet",
        description="Create a wallet for the authenticated user. If no mnemonic is provided, one will be generated.",
        responses={201: dict}
    )
    @action(detail=False, methods=["post"])
    def create_wallet(self, request):
        user = request.user
        mnemonic = request.data.get("mnemonic")
        network = request.data.get("network", "testnet")

        try:
            wallet, mnemonic_out = Wallet.create_wallet_for_user(
                user=user,
                mnemonic=mnemonic,
                network=network
            )
            log_wallet_activity(user, "wallet_created", {"wallet_name": wallet.wallet_name, "network": network})
            return Response(
                create_success_response({
                    "wallet_name": wallet.wallet_name,
                    "bitcoin_address": wallet.bitcoin_address,
                    "network": wallet.network,
                    "mnemonic": mnemonic_out
                }, "Wallet created successfully"),
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Wallet creation failed for {user.username}: {e}")
            return Response(
                create_error_response("Wallet creation failed", str(e)),
                status=status.HTTP_400_BAD_REQUEST
            )

    @extend_schema(
        operation_id='wallet_verify_mnemonic',
        summary='Verify mnemonic phrase',
        description='Verify the BIP39 mnemonic phrase provided by user by checking specific words.',
        request=VerifyMnemonicSerializer,
        responses={200: VerifyMnemonicSerializer}
    )
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsActiveUser])
    def verify_mnemonic(self, request):
        serializer = VerifyMnemonicSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                create_error_response("Invalid input", serializer.errors),
                status=status.HTTP_400_BAD_REQUEST
            )

        data = serializer.validated_data
        mnemonic_phrase = data["mnemonic"].strip().split()
        words_to_verify = data["words_to_verify"]

        errors = {}
        for index_str, word in words_to_verify.items():
            index = int(index_str)
            if index >= len(mnemonic_phrase) or mnemonic_phrase[index] != word:
                errors[index_str] = f"Expected '{mnemonic_phrase[index]}' but got '{word}'"

        if errors:
            return Response(
                create_error_response("Mnemonic verification failed", errors),
                status=status.HTTP_400_BAD_REQUEST
            )

        log_wallet_activity(request.user, "mnemonic_verified", {"verified_words": list(words_to_verify.keys())})
        return Response(
            create_success_response(True, "Mnemonic verified successfully"),
            status=status.HTTP_200_OK
        )

    @extend_schema(
        operation_id='wallet_restore',
        summary='Restore wallet',
        description='Restore a Bitcoin wallet from mnemonic or private key',
        responses={201: dict}
    )
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsActiveUser])
    def restore(self, request):
        """
        Restore a Bitcoin wallet for the authenticated user.
        Expects 'wallet_name' and 'keys' in request.data.
        """
        keys = request.data.get("keys",'')
        network = request.data.get("network", getattr(settings, "BITCOIN_NETWORK", "testnet"))


        try:
            with transaction.atomic():
                wallet = Wallet.restore_wallet_for_user(
                    user=request.user,
                    keys=keys,
                    network=network
                )
                log_wallet_activity(request.user, 'wallet_restored', {
                    'wallet_name': wallet.wallet_name,
                    'network': wallet.network
                })
                return Response(
                    create_success_response({
                        "wallet_name": wallet.wallet_name,
                        "bitcoin_address": wallet.bitcoin_address,
                        "network": wallet.network,
                        "balance": str(wallet.balance)
                    }, "Wallet restored successfully"),
                    status=status.HTTP_201_CREATED
                )
        except Exception as e:
            logger.error(f"Wallet restoration error for {request.user.username}: {e}")
            return Response(
                create_error_response("Failed to restore wallet. Please try again.", str(e)),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    @extend_schema(
        operation_id='wallet_balance',
        summary='Get wallet balance',
        description='Get current wallet balance',
        responses={200: WalletBalanceSerializer}
    )
    @action(detail=False, methods=['get'])
    def balance(self, request):
        wallet = self.get_wallet()
        try:
            wallet.update_balance()
            return Response(
                create_success_response(WalletBalanceSerializer(wallet).data, "Balance retrieved successfully"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Failed to retrieve balance for {request.user.username}: {e}")
            return Response(
                create_error_response("Failed to retrieve balance", str(e)),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        operation_id='wallet_backup',
        summary='Backup wallet private key',
        description='Return wallet WIF for backup purposes',
        responses={200: dict}
    )
    @action(detail=False, methods=['get'])
    def backup(self, request):
        wallet = self.get_wallet()
        try:
            wif = wallet.service.backup_wallet()  # return WIF only
            return Response(
                create_success_response(wif, "Wallet backup retrieved successfully"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Failed to backup wallet for {request.user.username}: {e}")
            return Response(
                create_error_response("Failed to backup wallet", str(e)),
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
    def generate_address(self, request):
        serializer = AddressGenerationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                create_error_response("Invalid input", serializer.errors),
                status=status.HTTP_400_BAD_REQUEST
            )
        wallet = self.get_wallet()
        label = serializer.validated_data.get('label', '')
        try:
            address = wallet.generate_new_address(label)
            log_wallet_activity(request.user, 'address_generated', {'address': address})
            return Response(
                create_success_response({'address': address, 'label': label}, "Address generated successfully"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Address generation error: {e}")
            return Response(
                create_error_response("Failed to generate address", str(e)),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        operation_id='wallet_generate_qr_code',
        summary='Generate QR code for receiving payments',
        description='Generate a QR code for receiving Bitcoin payments',
        request=AddressGenerationSerializer,
        responses={200: dict}
    )
    @action(detail=False, methods=['post'])
    def generate_qr_code(self, request):
        serializer = AddressGenerationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                create_error_response("Invalid input", serializer.errors),
                status=status.HTTP_400_BAD_REQUEST
            )
        wallet = self.get_wallet()
        try:
            qr_data = wallet.service.generate_receive_qrcode(
                amount=request.data.get('amount'),
                address=wallet.bitcoin_address
            )
            log_wallet_activity(request.user, 'qr_code_generated', {'address': qr_data['address']})
            return Response(
                create_success_response(qr_data, "QR code generated successfully"),
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"QR code generation error: {e}")
            return Response(
                create_error_response("Failed to generate QR code", str(e)),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def estimate_fee(self, request):
        """
        Estimate network fee and sendable amount for a BTC transaction.
        Expects:
        - amount: amount in BTC
        """
        user = request.user
        try:
            wallet = Wallet.objects.get(user=user)
        except Wallet.DoesNotExist:
            return Response(
                {"error": "Wallet not found for this user."},
                status=status.HTTP_404_NOT_FOUND
            )

        amount = request.data.get("amount")
        if not amount:
            return Response(
                {"error": "Amount is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            amount = Decimal(amount)

            # Estimate network fee and sendable amount
            estimation = wallet.service.estimate_sendable_amount(amount)

            sendable_btc = f"{estimation['sendable_amount']:.8f}"
            network_fee_btc = f"{estimation['fee']:.8f}"

            # Convert to USD & BIF
            from .utils import convert_btc_to_usd_bif
            sendable_converted = convert_btc_to_usd_bif(estimation['sendable_amount'])
            fee_converted = convert_btc_to_usd_bif(estimation['fee'])

            data = {
                "sendable_btc": sendable_btc,
                "network_fee_btc": network_fee_btc,
                "sendable_usd": sendable_converted['usd'],
                "sendable_bif": sendable_converted['bif'],
                "network_fee_usd": fee_converted['usd'],
                "network_fee_bif": fee_converted['bif']
            }
            return Response(create_success_response(data, "Fee estimation successful"))

        except Exception as e:
            logger.error(f"Fee estimation error: {e}")
            return Response(
                {"success": False, "error": f"Failed to estimate fees: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class TransactionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for transaction operations."""
    
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return only the current user's transactions."""
        wallet = Wallet.objects.get(user=self.request.user)
        wallet.sync_transactions()
        return wallet.transactions.all().order_by('-created_at')
    
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
        operation_id="transaction_recents",
        summary="Recent transactions",
        description="Get the 5 most recent user transactions",
        responses={200: TransactionSerializer(many=True)},
    )
    @action(detail=False, methods=["get"])
    def recents(self, request):
        """Get the 5 most recent user transactions"""
        queryset = self.get_queryset()[:5]  # only last 5

        serializer = TransactionSerializer(queryset, many=True)
        return Response(
            create_success_response(
                serializer.data,
                "Recent transactions retrieved successfully"
            ),
            status=status.HTTP_200_OK
        )
    @extend_schema(
        operation_id='transaction_send',
        summary='Send Bitcoin transaction',
        description='Send Bitcoin to specified address with optional service fee',
        request=SendTransactionSerializer,
        responses={201: TransactionSerializer}
    )
    @action(detail=False, methods=['post'])
    def send(self, request: Request) -> Response:
        print(request.data)
        """Send Bitcoin transaction."""
        try:
            wallet = Wallet.objects.get(user=request.user)
            
            address = request.data['to_address']
            amount = Decimal(request.data["amount"])
        
            transaction_obj = wallet.send_transaction(address, amount)
            
            log_wallet_activity(request.user, 'transaction_sent', {
               
                'amount': str(amount),
                'address': address,
            })
            
            return Response(
                create_success_response(
                   
                    f"Transaction sent successfully! "
                ),
                status=status.HTTP_201_CREATED
            )
            
        except InsufficientFundsError as e:
            logger.error(f"Insufficient funds error: {e}")
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
        try:
            wallet = Wallet.objects.get(user=self.request.user)
            synced_count = wallet.sync_transactions()
            
            log_wallet_activity(request.user, 'transactions_synced', {
                'synced_count': synced_count
            })
            
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
    
    @extend_schema(
        operation_id='transaction_track',
        summary='Track transaction status',
        description='Track the status of a specific transaction',
        parameters=[
            OpenApiParameter(
                name='txid',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description='Transaction ID to track'
            )
        ],
        responses={200: dict}
    )
    @action(detail=False, methods=['get'], url_path='track/(?P<txid>[^/.]+)')
    def track(self, request: Request, txid: str) -> Response:
        """Track a specific transaction's status."""
        try:
            wallet = Wallet.objects.get(user=self.request.user)
            tx_status = wallet.service.track_transaction(txid)
            
            log_wallet_activity(request.user, 'transaction_tracked', {
                'txid': txid,
                'status': tx_status.get('status', 'unknown')
            })
            
            return Response(
                create_success_response(
                    tx_status,
                    f"Transaction status retrieved for TXID: {txid}"
                ),
                status=status.HTTP_200_OK
            )
            
        except BitcoinRPCError as e:
            logger.error(f"Transaction tracking error: {e}")
            return Response(
                create_error_response(f"Error tracking transaction: {str(e)}"),
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )