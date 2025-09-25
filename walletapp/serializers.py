from decimal import Decimal
from typing import Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from .models import Wallet, Transaction
from .utils import validate_bitcoin_address, is_valid_transaction_amount
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Wallet
from .bitcoin_service import BitcoinService
from .utils import validate_mnemonic, validate_private_key
from bitcoinlib.mnemonic import Mnemonic
from django.conf import settings
import requests
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
    """Serializer for user registration with validation."""

    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="Password must be at least 8 characters long"
    )

    email = serializers.EmailField(
        required=True,
        help_text="Valid email address required"
    )

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
        ]
        extra_kwargs = {
            'username': {
                'help_text': 'Unique username (3-150 characters)',
                'min_length': 3,
                'max_length': 150
            },
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

    def create(self, validated_data):
        """Create user (without wallet)."""
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
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
            'id', 'user', 'wallet_name', "status",'bitcoin_address', 'primary_address',
            'balance', 'balance_formatted', 'network', 'stats',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'wallet_name', 'bitcoin_address', 'primary_address',
           'balance', 'balance_formatted', 'stats', 'created_at', 'updated_at'
        ]
    
    def get_balance_formatted(self, obj) -> str:
        """Get formatted balance string."""
        return f"{obj.balance:.8f} BTC"
    
    def get_status(self, obj) -> str:
        """Get wallet status."""
        return 'active' if obj.bitcoin_address else 'inactive'
    
    def get_stats(self, obj) -> Dict[str, Any]:
        """Get wallet statistics."""
        return obj.get_stats()

class WalletBalanceSerializer(serializers.ModelSerializer):
    btc_value = serializers.SerializerMethodField()
    sats_value = serializers.SerializerMethodField()
    usd_value = serializers.SerializerMethodField()
    bif_value = serializers.SerializerMethodField()
    last_updated = serializers.DateTimeField(source='updated_at', read_only=True)

    class Meta:
        model = Wallet
        fields = [
            'id', 'wallet_name', 'bitcoin_address', 'balance',
            'btc_value', 'sats_value', 'usd_value', 'bif_value', 'last_updated'
        ]

    def get_btc_value(self, obj):
        return f"{obj.balance:.8f} BTC"

    def get_sats_value(self, obj):
        sats = int(obj.balance * 100_000_000)
        return f"{sats} sats"

    def get_usd_value(self, obj):
        try:
            url = f"https://api.yadio.io/convert/{obj.balance}/BTC/USD"
            response = requests.get(url)
            data = response.json()
            usd = round(data.get('result', 0), 2)
            return f"${usd} USD"
        except Exception:
            return None

    def get_bif_value(self, obj):
        try:
            # Convert BTC -> USD
            url_usd = f"https://api.yadio.io/convert/{obj.balance}/BTC/USD"
            usd_amount = requests.get(url_usd).json().get('result', 0)

            # Convert USD -> BIF
            url_bif = f"https://api.yadio.io/convert/{usd_amount}/USD/BIF"
            bif_amount = requests.get(url_bif).json().get('result', 0)

            return f"{round(bif_amount, 2)} BIF"
        except Exception:
            return None


class TransactionSerializer(serializers.ModelSerializer):
    """Comprehensive transaction serializer."""
    
    wallet_owner = serializers.CharField(source='wallet.user.username', read_only=True)
    amount_formatted = serializers.SerializerMethodField()
    absolute_amount = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    is_confirmed = serializers.SerializerMethodField()
    explorer_url = serializers.SerializerMethodField()
    fee_formatted = serializers.SerializerMethodField()
    service_fee_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'wallet', 'wallet_owner', 'txid', 'transaction_type', 'amount',
            'amount_formatted', 'absolute_amount', 'fee', 'fee_formatted',
            'service_fee', 'service_fee_formatted', 'from_address', 'to_address',
            'status', 'is_confirmed', 'confirmations', 'raw_tx', 'tx_size_bytes',
            'explorer_url', 'comment', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'wallet', 'wallet_owner', 'txid', 'transaction_type', 'amount',
            'amount_formatted', 'absolute_amount', 'fee', 'fee_formatted',
            'service_fee', 'service_fee_formatted', 'from_address', 'to_address',
            'status', 'is_confirmed', 'confirmations', 'raw_tx', 'tx_size_bytes',
            'explorer_url', 'created_at', 'updated_at'
        ]
    
    def get_amount_formatted(self, obj) -> str:
        """Get formatted BTC amount without unnecessary trailing zeros."""
        # Format with 8 decimals, then strip trailing zeros
        formatted = f"{obj.amount:.8f}".rstrip('0').rstrip('.')
        return f"{formatted} BTC"

    
    def get_absolute_amount(self, obj) -> str:
        """Get absolute amount (always positive)."""
        return f"{obj.absolute_amount:.8f}".rstrip('0').rstrip('.')+" BTC"
    
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
        return f"{obj.fee:.8f}".rstrip('0').rstrip('.')+ "BTC"
    
    def get_service_fee_formatted(self, obj) -> str:
        """Get formatted service fee string."""
        return f"{obj.service_fee:.8f}".rstrip('0').rstrip('.')+ " BTC"

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
   

    def validate_address(self, value):
        """Validate Bitcoin address."""
        if not validate_bitcoin_address(value):
            raise serializers.ValidationError("Invalid Bitcoin address format")
        return value
    
    def validate_amount(self, value):
        """Validate transaction amount."""
        if not is_valid_transaction_amount(value):
            min_amount = getattr(settings, 'WALLET_SETTINGS', {}).get('MIN_TRANSACTION_AMOUNT', Decimal('0.00000001'))
            raise serializers.ValidationError(
                f"Amount must be at least {min_amount} BTC"
            )
        return value

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


class GenerateMnemonicSerializer(serializers.Serializer):
    """Serializer for generating BIP39 mnemonic phrases."""
    words = serializers.ChoiceField(
        choices=[12, 24],
        default=12,
        help_text="Number of words for the mnemonic (12 or 24)"
    )
    language = serializers.CharField(
        default="english",
        max_length=20,
        help_text="Language for the mnemonic (e.g., 'english', 'spanish')"
    )


    def create(self, validated_data):
        """Generate mnemonic phrase using BitcoinService."""
        return BitcoinService.generate_mnemonic(
            words=validated_data['words'],
            language=validated_data['language']
        )
class CreateWalletSerializer(serializers.Serializer):
    """Serializer for creating a new Bitcoin wallet."""
    wallet_name = serializers.CharField(
        max_length=100,
        required=False,
        help_text="Unique name for the wallet (auto-generated if not provided)"
    )
    passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=100,
        help_text="Optional passphrase for wallet encryption"
    )
    mnemonic = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=500,
        help_text="Optional mnemonic phrase (12 or 24 words) if generate_mnemonic=False"
    )


class RestoreWalletSerializer(serializers.Serializer):
    """Serializer for restoring a Bitcoin wallet from mnemonic or private key."""
    wallet_name = serializers.CharField(
        max_length=100,
        help_text="Unique name for the restored wallet"
    )
    keys = serializers.CharField(
        required=True,
        max_length=1000,
        help_text="Mnemonic phrase (12/24 words) or WIF private key"
    )
    passphrase = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=100,
        help_text="Optional passphrase used during wallet creation"
    )

    def create(self, validated_data):
        """Restore wallet using BitcoinService."""
        user = self.context['request'].user
        wallet_name = validated_data['wallet_name']
        keys = validated_data['keys']
        passphrase = validated_data['passphrase']

        wallet = Wallet.restore_wallet_for_user(
            user=user,
            wallet_name=wallet_name,
            keys=keys,
            passphrase=passphrase,
        )

        return {
            'wallet': wallet,
            'address': wallet.bitcoin_address,
            'wallet_name': wallet.wallet_name,
            'network': wallet.network,
            'restored': True
        }


class WordVerifySerializer(serializers.Serializer):
    position = serializers.IntegerField(
        min_value=1, 
        help_text="The 1-based position of the word in the mnemonic"
    )
    word = serializers.CharField(
        max_length=20, 
        help_text="The word at the specified position to verify"
    )

class VerifyMnemonicSerializer(serializers.Serializer):
    mnemonic = serializers.CharField(
        max_length=255,
        help_text="The full mnemonic phrase"
    )
    words_to_verify = serializers.DictField(
        child=serializers.CharField(max_length=20),
        help_text="Dictionary mapping positions (0-based) to the word to verify"
    )

    def validate_words_to_verify(self, value):
        if len(value) != 4:
            raise serializers.ValidationError("Exactly 4 words must be provided for verification")
        # Ensure keys are integers
        for k in value.keys():
            if not k.isdigit():
                raise serializers.ValidationError("All keys in words_to_verify must be numeric indices")
        return value