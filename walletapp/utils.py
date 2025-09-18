import logging
from django.conf import settings
from decimal import Decimal
from bitcoinlib.keys import Address
from rest_framework.views import exception_handler
from django.utils import timezone
import logging
from django.conf import settings
from decimal import Decimal
from bitcoinlib.keys import Address, Key
from bitcoinlib.mnemonic import Mnemonic



logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom exception handler that provides consistent error responses.
    """
    response = exception_handler(exc, context)

    if response is not None:
        custom_response_data = {
            'success': False,
            'error': {
                'code': response.status_code,
                'message': 'An error occurred',
                'details': response.data
            },
            'timestamp': timezone.now().isoformat()
        }

        # Map HTTP status codes to messages
        status_messages = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            500: 'Internal Server Error',
        }
        if response.status_code in status_messages:
            custom_response_data['error']['message'] = status_messages[response.status_code]

        response.data = custom_response_data

        # Log the error with relevant context info
        logger.error(f"API Error: {exc}", extra={
            'status_code': response.status_code,
            'request_path': getattr(context.get('request'), 'path', None),
            'user': getattr(getattr(context.get('request'), 'user', None), 'username', None)
        })

    return response

def validate_bitcoin_address(address: str) -> bool:
    """Validate a Bitcoin address."""
    try:
        addr = Address.import_address(address)
        return True
    except Exception as e:
        logger.warning(f"Invalid Bitcoin address {address}: {e}")
        return False

def is_valid_transaction_amount(amount: Decimal) -> bool:
    """Validate transaction amount."""
    min_amount = getattr(settings, 'WALLET_SETTINGS', {}).get('MIN_TRANSACTION_AMOUNT', Decimal('0.00000001'))
    return amount >= min_amount

def create_success_response(data: dict = None, message: str = "") -> dict:
    """Create a standardized success response."""
    return {
        "success": True,
        "data": data or {},
        "message": message,
        "status_code": 200
    }

def create_error_response(message: str, errors: dict = None) -> dict:
    """Create a standardized error response."""
    return {
        "success": False,
        "data": {},
        "message": message,
        "errors": errors or {},
        "status_code": 400
    }

def log_wallet_activity(user, activity_type: str, extra_data: dict = None):
    """Log wallet-related activities."""
    log_message = f"User {user.username} performed {activity_type}"
    if extra_data:
        log_message += f" with details: {extra_data}"
    logger.info(log_message)

class BitcoinRPCError(Exception):
    """Custom exception for Bitcoin RPC errors."""
    pass

class InsufficientFundsError(Exception):
    """Custom exception for insufficient funds."""
    pass

class InvalidAddressError(Exception):
    """Custom exception for invalid Bitcoin address."""
    pass




def validate_mnemonic(mnemonic_str: str) -> bool:
    """Validate if the string is a valid BIP39 mnemonic."""
    try:
        mnemonic = Mnemonic()
        return mnemonic.check(mnemonic_str)
    except Exception:
        return False

def validate_private_key(key_str: str) -> bool:
    """Validate if the string is a valid WIF private key."""
    try:
        Key(key_str)
        return True
    except Exception:
        return False





