"""
Professional Bitcoin RPC client with error handling and logging.
"""

import logging
from typing import Optional, Dict, Any, List
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from django.conf import settings
from .utils import BitcoinRPCError, generate_bitcoin_qrcode

logger = logging.getLogger('wallet')


class BitcoinRPCClient:
    """
    Professional Bitcoin RPC client with comprehensive error handling.
    """
    
    def __init__(self, wallet_name: Optional[str] = None):
        self.wallet_name = wallet_name
        self.config = settings.BITCOIN_RPC
        self._connection = None
    
    def _get_connection(self) -> AuthServiceProxy:
        """
        Get or create RPC connection with error handling and auto wallet management.
        """
        base_url = f"http://{self.config['username']}:{self.config['password']}@{self.config['host']}:{self.config['port']}"

        def build_connection(wallet: Optional[str] = None) -> AuthServiceProxy:
            url = base_url
            if wallet:
                url += f"/wallet/{wallet}"
            return AuthServiceProxy(url, timeout=self.config['timeout'])

        try:
            if self.wallet_name:
                try:
                    # Try connecting directly to the wallet
                    conn = build_connection(self.wallet_name)
                    conn.getwalletinfo()
                    logger.info(f"Connected to existing wallet: {self.wallet_name}")
                    return conn
                except JSONRPCException:
                    # Try loading or creating the wallet
                    base_conn = build_connection()
                    try:
                        base_conn.loadwallet(self.wallet_name)
                        logger.info(f"Wallet {self.wallet_name} loaded successfully")
                    except JSONRPCException as e:
                        if "not found" in str(e) or "Wallet file not found" in str(e):
                            base_conn.createwallet(self.wallet_name)
                            logger.info(f"Wallet {self.wallet_name} created successfully")
                        elif "already loaded" in str(e):
                            logger.info(f"Wallet {self.wallet_name} is already loaded")
                        else:
                            raise BitcoinRPCError(f"Failed to load wallet: {e}")
                    # Return new connection to the loaded/created wallet
                    return build_connection(self.wallet_name)
            else:
                # No wallet specified; just connect to the node
                conn = build_connection()
                conn.getblockchaininfo()
                logger.info("Connected to Bitcoin RPC without wallet")
                return conn

        except JSONRPCException as e:
            logger.error(f"Bitcoin RPC JSON error: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"RPC JSON error: {e}")
        except Exception as e:
            logger.error(f"Bitcoin RPC connection error: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Connection error: {e}")

    @property
    def connection(self) -> AuthServiceProxy:
        if self._connection is None:
            self._connection = self._get_connection()
        return self._connection

    def create_wallet(self, wallet_name: str, passphrase: Optional[str] = None) -> bool:
        try:
            self.connection.createwallet(wallet_name, False, False, passphrase or "")
            logger.info(f"Created wallet: {wallet_name}")
            return True
        except JSONRPCException as e:
            if "already exists" in str(e):
                logger.info(f"Wallet {wallet_name} already exists")
                return True
            logger.error(f"Error creating wallet {wallet_name}: {e}")
            raise BitcoinRPCError(f"Failed to create wallet: {e}")

    def load_wallet(self, wallet_name: str) -> bool:
        try:
            self.connection.loadwallet(wallet_name)
            logger.info(f"Loaded wallet: {wallet_name}")
            return True
        except JSONRPCException as e:
            if "already loaded" in str(e):
                logger.info(f"Wallet {wallet_name} already loaded")
                return True
            logger.error(f"Error loading wallet {wallet_name}: {e}")
            raise BitcoinRPCError(f"Failed to load wallet: {e}")

    def get_balance(self) -> Decimal:
        try:
            balance = self.connection.getbalance()
            return Decimal(str(balance))
        except JSONRPCException as e:
            logger.error(f"Error getting balance: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Failed to get balance: {e}")

    def get_new_address(self, label: str = "") -> str:
        try:
            address = self.connection.getnewaddress(label)
            logger.info(f"Generated new address", extra={
                'wallet': self.wallet_name,
                'label': label
            })
            return address
        except JSONRPCException as e:
            logger.error(f"Error generating address: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Failed to generate address: {e}")

    def send_to_address(self, address: str, amount: Decimal, comment: str = "") -> str:
        try:
            self.connection.settxfee(float(settings.WALLET_SETTINGS['DEFAULT_TX_FEE']))
            txid = self.connection.sendtoaddress(address, float(amount), comment)
            logger.info(f"Sent transaction", extra={
                'wallet': self.wallet_name,
                'address': address,
                'amount': str(amount),
                'txid': txid
            })
            return txid
        except JSONRPCException as e:
            logger.error(f"Error sending transaction: {e}", extra={
                'wallet': self.wallet_name,
                'address': address,
                'amount': str(amount)
            })
            raise BitcoinRPCError(f"Failed to send transaction: {e}")
     # Inside class BitcoinRPCClient

    def generate_receive_qrcode(self, label: str = "", amount: Optional[Decimal] = None) -> Dict[str, str]:
        """
        Generate a new receive address and return its QR code.
        """
        try:
            address = self.get_new_address(label)
            qr = generate_bitcoin_qrcode(address, float(amount) if amount else None)
            return {
                "address": address,
                "qr_code": qr
            }
        except Exception as e:
            logger.error(f"Error generating receive QR code: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Failed to generate QR code: {e}")

    def list_transactions(self, count: int = 20, skip: int = 0) -> List[Dict[str, Any]]:
        try:
            transactions = self.connection.listtransactions("*", count, skip)
            logger.debug(f"Retrieved {len(transactions)} transactions", extra={
                'wallet': self.wallet_name
            })
            return transactions
        except JSONRPCException as e:
            logger.error(f"Error listing transactions: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Failed to list transactions: {e}")

    def get_transaction(self, txid: str) -> Dict[str, Any]:
        try:
            transaction = self.connection.gettransaction(txid)
            return transaction
        except JSONRPCException as e:
            logger.error(f"Error getting transaction {txid}: {e}", extra={'wallet': self.wallet_name})
            raise BitcoinRPCError(f"Failed to get transaction: {e}")

    def validate_address(self, address: str) -> Dict[str, Any]:
        try:
            return self.connection.validateaddress(address)
        except JSONRPCException as e:
            logger.error(f"Error validating address {address}: {e}")
            raise BitcoinRPCError(f"Failed to validate address: {e}")

    def get_blockchain_info(self) -> Dict[str, Any]:
        try:
            return self.connection.getblockchaininfo()
        except JSONRPCException as e:
            logger.error(f"Error getting blockchain info: {e}")
            raise BitcoinRPCError(f"Failed to get blockchain info: {e}")


def get_rpc(wallet_name: Optional[str] = None) -> BitcoinRPCClient:
    return BitcoinRPCClient(wallet_name)


def ensure_wallet_exists(wallet_name: str) -> bool:
    """
    Ensure a wallet exists, creating it if necessary.
    """
    try:
        rpc = get_rpc(wallet_name)
        rpc.connection.getwalletinfo()  # This will trigger creation/loading via __init__
        return True
    except Exception as e:
        logger.error(f"Error ensuring wallet exists: {e}", extra={'wallet': wallet_name})
        return False
