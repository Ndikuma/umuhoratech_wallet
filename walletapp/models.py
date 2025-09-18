from django.db import models
from django.conf import settings
from decimal import Decimal
from .bitcoin_service import BitcoinService
import logging
from django.utils import timezone
logger = logging.getLogger(__name__)

class Wallet(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="wallet"
    )
    wallet_name = models.CharField(max_length=100, unique=True)
    bitcoin_address = models.CharField(max_length=62, blank=True, null=True)
    balance = models.DecimalField(max_digits=16, decimal_places=8, default=Decimal("0.0"))
    network = models.CharField(max_length=20, default="testnet")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.username} - {self.wallet_name}"

    @property
    def service(self):
        """Return BitcoinService instance for this wallet"""
        fee_address = getattr(settings, "FEE_ADDRESS", None)
        if not fee_address:
            raise ValueError("FEE_ADDRESS is not configured in settings")
        return BitcoinService(wallet_name=self.wallet_name, fee_address=fee_address, network=self.network)

    @classmethod
    def create_wallet_for_user(cls, user, wallet_name=None, mnemonic=None, passphrase="", network="testnet"):
        """Create a wallet for a user using BitcoinService"""
        if not wallet_name:
            wallet_name = f"{user.username}_wallet_{int(time.time())}"
        try:
            btc_service = BitcoinService(network=network, fee_address=settings.FEE_ADDRESS)
            wallet_data = btc_service.create_wallet(wallet_name, mnemonic=mnemonic, passphrase=passphrase)
            wallet = cls.objects.create(
                user=user,
                wallet_name=wallet_name,
                bitcoin_address=wallet_data["address"],
                network=network
            )
            logger.info(f"Wallet created for user {user.username}: {wallet_name}")
            return wallet, wallet_data.get("mnemonic", mnemonic)
        except Exception as e:
            logger.error(f"Failed to create wallet for user {user.username}: {e}")
            raise

    @classmethod
    def restore_wallet_for_user(cls, user, wallet_name, keys, passphrase="", network="testnet"):
        """Restore a wallet for a user using BitcoinService"""
        try:
            btc_service = BitcoinService(network=network, fee_address=settings.FEE_ADDRESS)
            wallet_data = btc_service.restore_wallet(wallet_name, keys, passphrase)
            wallet, created = cls.objects.get_or_create(
                user=user,
                wallet_name=wallet_name,
                defaults={
                    "bitcoin_address": wallet_data["address"],
                    "network": network
                }
            )
            if not created:
                wallet.bitcoin_address = wallet_data["address"]
                wallet.network = network
                wallet.save()
            logger.info(f"Wallet restored for user {user.username}: {wallet_name}")
            return wallet
        except Exception as e:
            logger.error(f"Failed to restore wallet for user {user.username}: {e}")
            raise

    def update_balance(self):
        """Fetch and update balance using BitcoinService"""
        try:
            balance_data = self.service.get_balance()
            self.balance = Decimal(balance_data.get("btc", 0.0))
            self.save(update_fields=["balance", "updated_at"])
            logger.info(f"Balance updated for wallet {self.wallet_name}: {self.balance} BTC")
            return self.balance
        except Exception as e:
            logger.error(f"Failed to update balance for wallet {self.wallet_name}: {e}")
            raise

    def generate_new_address(self, label=None):
        """Generate new receiving address using BitcoinService"""
        try:
            address_data = self.service.get_new_address(label=label)
            self.bitcoin_address = address_data["address"]
            self.save(update_fields=["bitcoin_address", "updated_at"])
            logger.info(f"New address generated for wallet {self.wallet_name}: {self.bitcoin_address}")
            return self.bitcoin_address
        except Exception as e:
            logger.error(f"Failed to generate new address for wallet {self.wallet_name}: {e}")
            raise

    def send_transaction(self, to_address, amount, comment="", broadcast=True):
        """Send BTC using BitcoinService (without service fee)"""
        try:
            tx_data = self.service.send_to_address(to_address, amount, broadcast=broadcast)
            tx = Transaction.objects.create(
                wallet=self,
                txid=tx_data["txid"],
                transaction_type="send",
                amount=Decimal(amount),
                fee=Decimal(tx_data.get("fees", 0.0)),
                service_fee=Decimal(0.0),
                from_address=tx_data.get("from_address"),
                to_address=to_address,
                status="pending" if not broadcast else "confirmed",
                raw_tx=tx_data.get("tx_hex"),
                tx_size_bytes=tx_data.get("tx_size_bytes", 0),
                explorer_url=tx_data.get("explorer_url"),
                comment=comment
            )
            self.update_balance()
            logger.info(f"Transaction sent from wallet {self.wallet_name}: {tx.txid}")
            return tx.txid
        except Exception as e:
            logger.error(f"Failed to send transaction from wallet {self.wallet_name}: {e}")
            raise

    def send_with_fee(self, to_address, amount, service_fee_percent=0.04, broadcast=True):
        """Send BTC with service fee using BitcoinService"""
        try:
            tx_data = self.service.send_with_service_fee(
                to_address,
                amount,
                service_fee_percent=service_fee_percent,
                broadcast=broadcast
            )
            tx = Transaction.objects.create(
                wallet=self,
                txid=tx_data["txid"],
                transaction_type="send",
                amount=Decimal(amount),
                fee=Decimal(tx_data.get("network_fee_sats", 0)) / Decimal(1e8),
                service_fee=Decimal(tx_data.get("service_fee_sats", 0)) / Decimal(1e8),
                from_address=self.bitcoin_address,
                to_address=to_address,
                status="pending" if not broadcast else "confirmed",
                raw_tx=tx_data.get("raw_hex"),
                tx_size_bytes=tx_data.get("tx_size_bytes", 0),
                explorer_url=tx_data.get("explorer_url"),
            )
            self.update_balance()
            logger.info(f"Transaction with service fee sent from wallet {self.wallet_name}: {tx.txid}")
            return tx
        except Exception as e:
            logger.error(f"Failed to send transaction with service fee from wallet {self.wallet_name}: {e}")
            raise

    def sync_transactions(self):
        """Sync all transactions from Bitcoin network"""
        try:
            tx_data = self.service.list_transactions()  # Get all transactions
            transactions = tx_data.get("transactions", [])
            synced_count = 0

            for tx in transactions:
                tx_obj, created = Transaction.objects.update_or_create(
                    txid=tx["txid"],
                    defaults={
                        "wallet": self,
                        "transaction_type": tx.get("direction", "receive"),
                        "amount": Decimal(tx.get("value_btc")),
                        "fee": Decimal(tx.get("fee_btc", 0.0)),
                        "service_fee": Decimal(tx.get("service_fee", 0.0)),
                        "from_address": tx.get("input_address", ""),
                        "to_address": tx.get("output_address", self.bitcoin_address),
                        "status": "confirmed" if tx.get("status", {}).get("confirmed") else "pending",
                        "confirmations": tx.get("status", {}).get("confirmations", 0),
                        "raw_tx": tx.get("raw_hex"),
                        "tx_size_bytes": tx.get("size", 0),
                        "explorer_url": tx.get("explorer_url"),
                        "comment": tx.get("comment", ""),
                    }
                )
                if created:
                    synced_count += 1

            logger.info(f"Synced {synced_count} new transactions for wallet {self.wallet_name}")
            return synced_count

        except Exception as e:
            logger.error(f"Failed to sync transactions for wallet {self.wallet_name}: {e}")
            raise


    def get_stats(self):
        """Get wallet statistics"""
        try:
            wallet_info = self.service.get_wallet_info()
            transactions = self.transactions.all()
            sent_txs = transactions.filter(transaction_type="send")
            received_txs = transactions.filter(transaction_type="receive")
            return {
                "total_transactions": wallet_info["transactions_count"],
                "sent_transactions": sent_txs.count(),
                "received_transactions": received_txs.count(),
                "total_sent": Decimal(sum(tx.amount for tx in sent_txs)),
                "total_received": Decimal(sum(tx.amount for tx in received_txs)),
                "current_balance": self.balance,
                "wallet_age_days": (timezone.now() - self.created_at).days
            }
        except Exception as e:
            logger.error(f"Failed to get stats for wallet {self.wallet_name}: {e}")
            raise


class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ("send", "Send"),
        ("receive", "Receive"),
    ]
    
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    wallet = models.ForeignKey(
        Wallet,
        on_delete=models.CASCADE,
        related_name="transactions"
    )
    txid = models.CharField(max_length=64, unique=True)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=16, decimal_places=8)
    fee = models.DecimalField(max_digits=16, decimal_places=8, default=Decimal("0.0"))
    service_fee = models.DecimalField(max_digits=16, decimal_places=8, default=Decimal("0.0"))
    from_address = models.CharField(max_length=62, blank=True, null=True)
    to_address = models.CharField(max_length=62)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    confirmations = models.PositiveIntegerField(default=0)
    raw_tx = models.TextField(blank=True, null=True)
    tx_size_bytes = models.PositiveIntegerField(null=True, blank=True)
    explorer_url = models.URLField(blank=True, null=True)
    comment = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.txid[:10]}... - {self.transaction_type} - {self.amount} BTC"

    def update_status(self):
        """Update transaction status using BitcoinService"""
        try:
            tx_status = self.wallet.service.track_transaction(self.txid)
            self.status = "completed" if tx_status.get("confirmed") else "pending"
            self.confirmations = tx_status.get("confirmations", 0)
            self.save(update_fields=["status", "confirmations", "updated_at"])
            logger.info(f"Transaction {self.txid} status updated: {self.status}")
        except Exception as e:
            logger.error(f"Failed to update transaction {self.txid} status: {e}")
            raise

    @property
    def absolute_amount(self):
        """Return absolute amount for display"""
        return abs(self.amount)

    @property
    def is_confirmed(self):
        """Check if transaction is confirmed"""
        return self.status == "confirmed"

    def get_explorer_url(self):
        """Get blockchain explorer URL"""
        if self.explorer_url:
            return self.explorer_url
        return f"https://blockstream.info/{'testnet/' if self.wallet.network == 'testnet' else ''}tx/{self.txid}"