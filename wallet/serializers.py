"""
Professional serializers for Bitcoin Mini Wallet API with comprehensive validation.
"""

from decimal import Decimal
from typing import Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from .models import Wallet, Transaction
from .utils import validate_bitcoin_address, is_valid_transaction_amount


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user information."""
    
    full_name = serializers.SerializerMethodField()
    wallet_created = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'full_name', 'date_joined', 'last_login', 'is_active',
            'wallet_created'
        ]
        read_only_fields = [
            'id', 'date_joined', 'last_login', 'full_name', 'wallet_created'
        ]
    
    def get_full_name(self, obj) -> str:
        """Get user's full name."""
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username
    
    def get_wallet_created(self, obj) -> bool:
        """Check if user has a wallet."""
        return hasattr(obj, 'wallet')


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration with comprehensive validation."""
    
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="Password must be at least 8 characters long"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        help_text="Confirm your password"
    )
    email = serializers.EmailField(
        required=True,
        help_text="Valid email address required"
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password_confirm'
        ]
        extra_kwargs = {
            'username': {
                'help_text': 'Unique username (3-150 characters)',
                'min_length': 3,
                'max_length': 150
            },
            'first_name': {'required': False},
            'last_name': {'required': False},
        }
    
    def validate_username(self, value):
        """Validate username uniqueness and format."""
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Username already exists")
        
        if not value.replace('_', '').replace('-', '').isalnum():
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, hyphens, and underscores"
            )
        
        return value.lower()
    
    def validate_email(self, value):
        """Validate email uniqueness."""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered")
        return value.lower()
    
    def validate_password(self, value):
        """Validate password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': "Passwords don't match"
            })
        return attrs
    
    def create(self, validated_data):
        """Create user and associated wallet."""
        validated_data.pop('password_confirm')
        
        user = User.objects.create_user(**validated_data)
        
        # Create wallet for the user
        Wallet.objects.create_wallet_for_user(user)
        
        return user


class WalletSerializer(serializers.ModelSerializer):
    """Comprehensive wallet serializer."""
    
    user = UserSerializer(read_only=True)
    balance_formatted = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    stats = serializers.SerializerMethodField()
    primary_address = serializers.CharField(source='bitcoin_address', read_only=True)
    
    class Meta:
        model = Wallet
        fields = [
            'id', 'user', 'wallet_name', 'bitcoin_address', 'primary_address',
            'balance', 'balance_formatted', 'is_active', 'status',
            'last_sync', 'created_at', 'updated_at', 'stats'
        ]
        read_only_fields = [
            'id', 'user', 'wallet_name', 'balance', 'balance_formatted',
            'last_sync', 'created_at', 'updated_at', 'stats', 'status'
        ]
    
    def get_balance_formatted(self, obj) -> str:
        """Get formatted balance string."""
        return f"{obj.balance:.8f} BTC"
    
    def get_status(self, obj) -> str:
        """Get wallet status."""
        if not obj.is_active:
            return 'inactive'
        return 'active'
    
    def get_stats(self, obj) -> Dict[str, Any]:
        """Get wallet statistics."""
        return obj.get_stats()


class WalletBalanceSerializer(serializers.ModelSerializer):
    """Serializer for wallet balance information."""
    
    balance_formatted = serializers.SerializerMethodField()
    last_updated = serializers.DateTimeField(source='updated_at', read_only=True)
    
    class Meta:
        model = Wallet
        fields = ['balance', 'balance_formatted', 'last_updated']
        read_only_fields = ['balance', 'balance_formatted', 'last_updated']
    
    def get_balance_formatted(self, obj) -> str:
        """Get formatted balance string."""
        return f"{obj.balance:.8f} BTC"


class TransactionSerializer(serializers.ModelSerializer):
    """Comprehensive transaction serializer."""
    
    wallet_owner = serializers.CharField(source='wallet.user.username', read_only=True)
    amount_formatted = serializers.SerializerMethodField()
    absolute_amount = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    is_confirmed = serializers.SerializerMethodField()
    explorer_url = serializers.SerializerMethodField()
    fee_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'wallet', 'wallet_owner', 'txid', 'amount', 'amount_formatted',
            'absolute_amount', 'transaction_type', 'address', 'confirmations',
            'status', 'is_confirmed', 'fee', 'fee_formatted', 'comment',
            'timestamp', 'created_at', 'updated_at', 'explorer_url'
        ]
        read_only_fields = [
            'id', 'wallet', 'wallet_owner', 'txid', 'confirmations',
            'timestamp', 'created_at', 'updated_at', 'amount_formatted',
            'absolute_amount', 'status', 'is_confirmed', 'explorer_url',
            'fee_formatted'
        ]
    
    def get_amount_formatted(self, obj) -> str:
        """Get formatted amount string."""
        return f"{obj.amount:.8f} BTC"
    
    def get_absolute_amount(self, obj) -> str:
        """Get absolute amount (always positive)."""
        return f"{obj.absolute_amount:.8f} BTC"
    
    def get_status(self, obj) -> str:
        """Get transaction status."""
        return obj.status
    
    def get_is_confirmed(self, obj) -> bool:
        """Check if transaction is confirmed."""
        return obj.is_confirmed
    
    def get_explorer_url(self, obj) -> str:
        """Get blockchain explorer URL."""
        return obj.get_explorer_url()
    
    def get_fee_formatted(self, obj) -> str:
        """Get formatted fee string."""
        return f"{obj.fee:.8f} BTC"


class SendTransactionSerializer(serializers.Serializer):
    """Serializer for sending Bitcoin transactions."""
    
    address = serializers.CharField(
        max_length=62,
        help_text="Valid Bitcoin address"
    )
    amount = serializers.DecimalField(
        max_digits=16,
        decimal_places=8,
        min_value=Decimal('0.00000001'),
        help_text="Amount in BTC (minimum 0.00000001)"
    )
    comment = serializers.CharField(
        max_length=500,
        required=False,
        allow_blank=True,
        help_text="Optional transaction comment"
    )
    
    def validate_address(self, value):
        """Validate Bitcoin address."""
        if not validate_bitcoin_address(value):
            raise serializers.ValidationError("Invalid Bitcoin address format")
        return value
    
    def validate_amount(self, value):
        """Validate transaction amount."""
        if not is_valid_transaction_amount(value):
            min_amount = settings.WALLET_SETTINGS['MIN_TRANSACTION_AMOUNT']
            raise serializers.ValidationError(
                f"Amount must be at least {min_amount} BTC"
            )
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        # Additional validation can be added here
        return attrs


class AddressGenerationSerializer(serializers.Serializer):
    """Serializer for generating new Bitcoin addresses."""
    
    label = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        help_text="Optional label for the address"
    )


class TransactionSyncSerializer(serializers.Serializer):
    """Serializer for transaction sync operations."""
    
    limit = serializers.IntegerField(
        default=50,
        min_value=1,
        max_value=100,
        help_text="Number of transactions to sync (1-100)"
    )


class WalletStatsSerializer(serializers.Serializer):
    """Serializer for wallet statistics."""
    
    total_transactions = serializers.IntegerField(read_only=True)
    sent_transactions = serializers.IntegerField(read_only=True)
    received_transactions = serializers.IntegerField(read_only=True)
    total_sent = serializers.DecimalField(max_digits=16, decimal_places=8, read_only=True)
    total_received = serializers.DecimalField(max_digits=16, decimal_places=8, read_only=True)
    current_balance = serializers.DecimalField(max_digits=16, decimal_places=8, read_only=True)
    wallet_age_days = serializers.IntegerField(read_only=True)


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    
    username = serializers.CharField(
        max_length=150,
        help_text="Your username"
    )
    password = serializers.CharField(
        style={'input_type': 'password'},
        help_text="Your password"
    )
    
    def validate(self, attrs):
        """Validate login credentials."""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if not username or not password:
            raise serializers.ValidationError("Username and password are required")
        
        return attrs


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    
    old_password = serializers.CharField(
        style={'input_type': 'password'},
        help_text="Current password"
    )
    new_password = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'},
        help_text="New password (minimum 8 characters)"
    )
    new_password_confirm = serializers.CharField(
        style={'input_type': 'password'},
        help_text="Confirm new password"
    )
    
    def validate_new_password(self, value):
        """Validate new password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': "New passwords don't match"
            })
        return attrs