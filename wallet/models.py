"""
Professional Bitcoin wallet models with comprehensive validation and methods.
"""

import uuid
import logging
from decimal import Decimal
from typing import Optional, Dict, Any, List
from django.db import models, transaction
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, RegexValidator
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime
from django.conf import settings
from .rpc_client import get_rpc, ensure_wallet_exists
from .utils import (
    BitcoinRPCError,
    InsufficientFundsError,
    log_wallet_activity
)

logger = logging.getLogger('wallet')


class WalletManager(models.Manager):
    """Custom manager for Wallet model."""
    
    def create_wallet_for_user(self, user: User) -> 'Wallet':
        """
        Create a new wallet for a user with proper Bitcoin wallet setup.
        """
        try:
            with transaction.atomic():
                # Ensure Bitcoin wallet exists
                wallet_name = f"user_{user.id}_{user.username}"
                ensure_wallet_exists(wallet_name)
                
                # Create database wallet record
                wallet = self.create(
                    user=user,
                    wallet_name=wallet_name
                )
                
                # Generate initial Bitcoin address
                wallet.generate_new_address()
                
                log_wallet_activity(user, 'wallet_created', {
                    'wallet_id': wallet.id,
                    'wallet_name': wallet_name
                })
                
                return wallet
                
        except Exception as e:
            logger.error(f"Error creating wallet for user {user.username}: {e}")
            raise


class Wallet(models.Model):
    """
    Professional Bitcoin wallet model with comprehensive functionality.
    """
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='wallet'
    )
    wallet_name = models.CharField(
        max_length=100,
        unique=True,
        blank=True,
        null=True,
        help_text="Bitcoin Core wallet name"
    )
    bitcoin_address = models.CharField(
        max_length=62,
        blank=True,
        null=True,
        validators=[RegexValidator(
            regex=r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$|^tb1[a-z0-9]{39,59}$',
            message='Invalid Bitcoin address format'
        )],
        help_text="Primary Bitcoin address for receiving funds"
    )
    balance = models.DecimalField(
        max_digits=16,
        decimal_places=8,
        default=Decimal('0.00000000'),
        validators=[MinValueValidator(Decimal('0'))],
        help_text="Current wallet balance in BTC"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether the wallet is active"
    )
    last_sync = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time wallet was synced with Bitcoin network"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = WalletManager()
    
    class Meta:
        db_table = 'wallet_wallet'
        verbose_name = 'Bitcoin Wallet'
        verbose_name_plural = 'Bitcoin Wallets'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username}'s Wallet ({self.balance} BTC)"
    
        
        
    
    def save(self, *args, **kwargs):
        """Override save to ensure wallet name is set."""
        if not self.wallet_name:
            self.wallet_name = f"user_{self.user.id}_{self.user.username}"
        super().save(*args, **kwargs)
    
    @property
    def rpc_client(self):
        if ensure_wallet_exists(self.wallet_name):
            return get_rpc(self.wallet_name)
        else:
            logger.error(f"Wallet '{self.wallet_name}' could not be loaded or created.")
            raise BitcoinRPCError(f"Wallet '{self.wallet_name}' is not available.")

    
    def update_balance(self) -> Decimal:
        """
        Update wallet balance from Bitcoin network.
        """
        try:
            rpc = self.rpc_client
            new_balance = rpc.get_balance()
            
            if new_balance != self.balance:
                old_balance = self.balance
                self.balance = new_balance
                self.last_sync = timezone.now()
                self.save(update_fields=['balance', 'last_sync', 'updated_at'])
                
                log_wallet_activity(self.user, 'balance_updated', {
                    'old_balance': str(old_balance),
                    'new_balance': str(new_balance),
                    'wallet_id': self.id
                })
            
            return self.balance
            
        except BitcoinRPCError as e:
            logger.error(f"Error updating balance for wallet {self.id}: {e}")
            raise
    
    def generate_new_address(self, label: str = "") -> str:
        """
        Generate a new Bitcoin address for this wallet.
        """
        try:
            rpc = self.rpc_client
            new_address = rpc.get_new_address(label or f"user_{self.user.username}")
            
            # Update primary address if not set
            if not self.bitcoin_address:
                self.bitcoin_address = new_address
                self.save(update_fields=['bitcoin_address', 'updated_at'])
            
            log_wallet_activity(self.user, 'address_generated', {
                'address': new_address,
                'label': label,
                'wallet_id': self.id
            })
            
            return new_address
            
        except BitcoinRPCError as e:
            logger.error(f"Error generating address for wallet {self.id}: {e}")
            raise
    
    def send_transaction(self, to_address: str, amount: Decimal, comment: str = "") -> str:
        """
        Send Bitcoin transaction.
        """
        try:
            # Validate inputs
           
            
            if amount <= 0:
                raise ValidationError("Amount must be positive")
            
            # Update balance first
            current_balance = self.update_balance()
            
            # Check sufficient funds (including fee)
            fee = Decimal(str(settings.WALLET_SETTINGS['DEFAULT_TX_FEE']))
            total_needed = amount + fee
            
            if current_balance < total_needed:
                raise InsufficientFundsError(
                    f"Insufficient funds. Need {total_needed} BTC, have {current_balance} BTC"
                )
            
            # Send transaction
            rpc = self.rpc_client
            txid = rpc.send_to_address(to_address, amount, comment)
            
            # Create transaction record
            transaction_obj = Transaction.objects.create(
                wallet=self,
                txid=txid,
                amount=-amount,  # Negative for outgoing
                transaction_type='send',
                address=to_address,
                confirmations=0,
                timestamp=timezone.now(),
                fee=fee,
                comment=comment
            )
            
            # Update balance after transaction
            self.update_balance()
            
            log_wallet_activity(self.user, 'transaction_sent', {
                'txid': txid,
                'amount': str(amount),
                'to_address': to_address,
                'wallet_id': self.id
            })
            
            return txid
            
        except (BitcoinRPCError, ValidationError, InsufficientFundsError) as e:
            logger.error(f"Error sending transaction from wallet {self.id}: {e}")
            raise
    
    def get_transaction_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get transaction history from Bitcoin network.
        """
        try:
            rpc = self.rpc_client
            transactions = rpc.list_transactions(count=limit)
            return transactions
        except BitcoinRPCError as e:
            logger.error(f"Error getting transaction history for wallet {self.id}: {e}")
            raise
    
    def sync_transactions(self) -> int:
        """
        Sync transactions from Bitcoin network to database.
        """
        try:
            rpc_transactions = self.get_transaction_history(100)
            synced_count = 0
            
            for tx in rpc_transactions:
                transaction_obj, created = Transaction.objects.get_or_create(
                    txid=tx['txid'],
                    defaults={
                        'wallet': self,
                        'amount': Decimal(str(tx['amount'])),
                        'transaction_type': 'receive' if tx['amount'] > 0 else 'send',
                        'address': tx.get('address', ''),
                        'confirmations': tx.get('confirmations', 0),
                        'timestamp': datetime.fromtimestamp(tx['time'], tz=datetime.timezone.utc),
                        'fee': Decimal(str(abs(tx.get('fee', 0)))),
                        'comment': tx.get('comment', '')
                    }
                )
                timezone
                if created:
                    synced_count += 1
                else:
                    # Update confirmations for existing transactions
                    if transaction_obj.confirmations != tx.get('confirmations', 0):
                        transaction_obj.confirmations = tx.get('confirmations', 0)
                        transaction_obj.save(update_fields=['confirmations'])
            
            # Update wallet balance and sync time
            self.update_balance()
            
            log_wallet_activity(self.user, 'transactions_synced', {
                'synced_count': synced_count,
                'wallet_id': self.id
            })
            
            return synced_count
            
        except BitcoinRPCError as e:
            logger.error(f"Error syncing transactions for wallet {self.id}: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive wallet statistics.
        """
        from .utils import get_wallet_stats
        return get_wallet_stats(self)


class Transaction(models.Model):
    """
    Professional Bitcoin transaction model.
    """
    
    TRANSACTION_TYPES = [
        ('send', 'Send'),
        ('receive', 'Receive'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('failed', 'Failed'),
    ]
    
    wallet = models.ForeignKey(
        Wallet,
        on_delete=models.CASCADE,
        related_name='transactions'
    )
    txid = models.CharField(
        max_length=64,
        unique=True,
        validators=[RegexValidator(
            regex=r'^[a-fA-F0-9]{64}$',
            message='Invalid transaction ID format'
        )],
        help_text="Bitcoin transaction ID"
    )
    amount = models.DecimalField(
        max_digits=16,
        decimal_places=8,
        help_text="Transaction amount in BTC (negative for outgoing)"
    )
    transaction_type = models.CharField(
        max_length=10,
        choices=TRANSACTION_TYPES
    )
    address = models.CharField(
        max_length=62,
        help_text="Bitcoin address (sender or recipient)"
    )
    confirmations = models.PositiveIntegerField(
        default=0,
        help_text="Number of network confirmations"
    )
    fee = models.DecimalField(
        max_digits=16,
        decimal_places=8,
        default=Decimal('0.00000000'),
        validators=[MinValueValidator(Decimal('0'))],
        help_text="Transaction fee in BTC"
    )
    comment = models.TextField(
        blank=True,
        help_text="Optional transaction comment"
    )
    timestamp = models.DateTimeField(
        help_text="Transaction timestamp from Bitcoin network"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'wallet_transaction'
        verbose_name = 'Bitcoin Transaction'
        verbose_name_plural = 'Bitcoin Transactions'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['wallet', '-timestamp']),
            models.Index(fields=['txid']),
            models.Index(fields=['transaction_type']),
        ]
    
    def __str__(self):
        return f"{self.transaction_type.title()} - {self.amount} BTC ({self.txid[:8]}...)"
    
    @property
    def status(self) -> str:
        """Get transaction status based on confirmations."""
        if self.confirmations == 0:
            return 'pending'
        elif self.confirmations >= 6:  # Generally considered confirmed
            return 'confirmed'
        else:
            return 'pending'
    
    @property
    def is_confirmed(self) -> bool:
        """Check if transaction is confirmed."""
        return self.confirmations >= 6
    
    @property
    def absolute_amount(self) -> Decimal:
        """Get absolute amount (always positive)."""
        return abs(self.amount)
    
    def get_explorer_url(self) -> str:
        """Get blockchain explorer URL for this transaction."""
        # This would depend on network (mainnet/testnet)
        base_url = "https://blockstream.info/testnet/tx/"  # For testnet
        return f"{base_url}{self.txid}"
    
    def update_confirmations(self) -> int:
        """
        Update confirmation count from Bitcoin network.
        """
        try:
            rpc = self.wallet.rpc_client
            tx_info = rpc.get_transaction(self.txid)
            
            new_confirmations = tx_info.get('confirmations', 0)
            if new_confirmations != self.confirmations:
                self.confirmations = new_confirmations
                self.save(update_fields=['confirmations', 'updated_at'])
            
            return self.confirmations
            
        except BitcoinRPCError as e:
            logger.error(f"Error updating confirmations for transaction {self.txid}: {e}")
            raise
