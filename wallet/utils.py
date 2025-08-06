"""
Utility functions and classes for the Bitcoin Mini Wallet API.
"""

import logging
from decimal import Decimal
from typing import Dict, Any, Optional
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger('wallet')


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
        
        # Handle specific error types
        if response.status_code == 400:
            custom_response_data['error']['message'] = 'Bad Request'
        elif response.status_code == 401:
            custom_response_data['error']['message'] = 'Unauthorized'
        elif response.status_code == 403:
            custom_response_data['error']['message'] = 'Forbidden'
        elif response.status_code == 404:
            custom_response_data['error']['message'] = 'Not Found'
        elif response.status_code == 500:
            custom_response_data['error']['message'] = 'Internal Server Error'
        
        response.data = custom_response_data
        
        # Log the error
        logger.error(f"API Error: {exc}", extra={
            'status_code': response.status_code,
            'request_path': context.get('request').path if context.get('request') else None,
            'user': context.get('request').user if context.get('request') else None
        })
    
    return response


def create_success_response(data: Any = None, message: str = "Success", status_code: int = 200) -> Dict[str, Any]:
    """
    Create a standardized success response format.
    """
    response_data = {
        'success': True,
        'message': message,
        'timestamp': timezone.now().isoformat()
    }
    
    if data is not None:
        response_data['data'] = data
    
    return response_data


def create_error_response(message: str, details: Any = None, status_code: int = 400) -> Dict[str, Any]:
    """
    Create a standardized error response format.
    """
    response_data = {
        'success': False,
        'error': {
            'code': status_code,
            'message': message,
            'timestamp': timezone.now().isoformat()
        }
    }
    
    if details is not None:
        response_data['error']['details'] = details
    
    return response_data


def validate_bitcoin_address(address: str) -> bool:
    """
    Basic Bitcoin address validation.
    This is a simplified validation - in production, use a proper Bitcoin library.
    """
    if not address:
        return False
    return True
 
def format_btc_amount(amount: Decimal) -> str:
    """
    Format BTC amount to 8 decimal places.
    """
    return f"{amount:.8f}"


def is_valid_transaction_amount(amount: Decimal) -> bool:
    """
    Validate if the transaction amount meets minimum requirements.
    """
    min_amount = Decimal(str(settings.WALLET_SETTINGS['MIN_TRANSACTION_AMOUNT']))
    return amount >= min_amount


def calculate_transaction_fee(amount: Decimal, fee_rate: Optional[Decimal] = None) -> Decimal:
    """
    Calculate transaction fee based on amount and fee rate.
    """
    if fee_rate is None:
        fee_rate = Decimal(str(settings.WALLET_SETTINGS['DEFAULT_TX_FEE']))
    
    return fee_rate


def log_wallet_activity(user, action: str, details: Dict[str, Any] = None):
    """
    Log wallet-related activities for audit purposes.
    """
    log_data = {
        'user': user.username if user else 'Anonymous',
        'action': action,
        'timestamp': timezone.now().isoformat()
    }
    
    if details:
        log_data.update(details)
    
    logger.info(f"Wallet Activity: {action}", extra=log_data)


def get_wallet_stats(wallet) -> Dict[str, Any]:
    """
    Get comprehensive wallet statistics.
    """
    from django.db import models
    
    total_transactions = wallet.transactions.count()
    sent_transactions = wallet.transactions.filter(transaction_type='send').count()
    received_transactions = wallet.transactions.filter(transaction_type='receive').count()
    
    # Calculate total sent and received amounts
    sent_amount = wallet.transactions.filter(
        transaction_type='send'
    ).aggregate(
        total=models.Sum('amount')
    )['total'] or Decimal('0')
    
    received_amount = wallet.transactions.filter(
        transaction_type='receive'
    ).aggregate(
        total=models.Sum('amount')
    )['total'] or Decimal('0')
    
    return {
        'total_transactions': total_transactions,
        'sent_transactions': sent_transactions,
        'received_transactions': received_transactions,
        'total_sent': abs(sent_amount),  # Make positive for display
        'total_received': received_amount,
        'current_balance': wallet.balance,
        'wallet_age_days': (timezone.now() - wallet.created_at).days
    }


class BitcoinRPCError(Exception):
    """Custom exception for Bitcoin RPC errors."""
    pass


class InsufficientFundsError(Exception):
    """Custom exception for insufficient funds."""
    pass


class InvalidAddressError(Exception):
    """Custom exception for invalid Bitcoin addresses."""
    pass


class TransactionError(Exception):
    """Custom exception for transaction-related errors."""
    pass