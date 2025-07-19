from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class BitcoinRPCClient:
    def __init__(self):
        self.rpc_connection = AuthServiceProxy(
            f"http://{settings.BITCOIN_RPC['username']}:{settings.BITCOIN_RPC['password']}"
            f"@{settings.BITCOIN_RPC['host']}:{settings.BITCOIN_RPC['port']}"
        )
    
    def get_balance(self, account=None):
        try:
            if account:
                return self.rpc_connection.getbalance(account)
            return self.rpc_connection.getbalance()
        except JSONRPCException as e:
            logger.error(f"RPC Error getting balance: {e}")
            return 0
    
    def send_to_address(self, address, amount):
        try:
            txid = self.rpc_connection.sendtoaddress(address, amount)
            return txid
        except JSONRPCException as e:
            logger.error(f"RPC Error sending to address: {e}")
            return None
    
    def get_new_address(self, account=None):
        try:
            if account:
                return self.rpc_connection.getnewaddress(account)
            return self.rpc_connection.getnewaddress()
        except JSONRPCException as e:
            logger.error(f"RPC Error getting new address: {e}")
            return None
    
    def get_transactions(self, account=None, count=10):
        try:
            if account:
                return self.rpc_connection.listtransactions(account, count)
            return self.rpc_connection.listtransactions("*", count)
        except JSONRPCException as e:
            logger.error(f"RPC Error getting transactions: {e}")
            return []
    
    def get_address_info(self, address):
        try:
            return self.rpc_connection.getaddressinfo(address)
        except JSONRPCException as e:
            logger.error(f"RPC Error getting address info: {e}")
            return None