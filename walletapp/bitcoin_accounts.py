from bitcoinlib.wallets import Wallet
from bitcoinlib.transactions import Transaction
import logging

logging.basicConfig(level=logging.INFO)

class PlatformWalletManager:
    def __init__(self, wallet_name='platform_wallet', network='testnet', witness_type='segwit'):
        """
        Initialize the platform wallet manager.
        Creates a platform wallet if it doesn't exist.
        """
        self.wallet_name = wallet_name
        self.network = network
        self.witness_type = witness_type

        try:
            self.wallet = Wallet(self.wallet_name)
            logging.info(f"Loaded existing wallet: {self.wallet_name}")
        except:
            self.wallet = Wallet.create(self.wallet_name, witness_type=self.witness_type, network=self.network)
            logging.info(f"Created new platform wallet: {self.wallet_name}")

    def create_user_account(self, username):
        """
        Creates a new account for a user.
        Returns account info with deposit address.
        """
        account = self.wallet.new_account(username)

        logging.info(f"Created account '{username}' with deposit address {account.address}")
        return {
            
            'account_name': account.name,
            'deposit_address': account.address,
            'accout_wif': account.wif
            
        }

    def get_account_balance(self, account_id):
        """
        Returns balance of a specific account in satoshis.
        """
        balance = self.wallet.balance(account_id=account_id)
        return balance

    def list_accounts(self):
        """
        List all accounts with balances.
        """
        result = []
        for ac in self.wallet.accounts():
            if ac==0:
                continue
            acc =self.wallet.account(ac)
            result.append(
                acc.as_dict()
            )
        return result

    def get_utxos(self, account_id):
        """
        Returns all unspent outputs for an account.
        """
        account = [a for a in self.wallet.accounts() if a.account_id == account_id][0]
        return account.utxos()

    def send(self, account_id, to_address, amount_satoshi, fee_rate='fastest', subtract_fee=True):
        """
        Sends funds from a specific account.
        Automatically handles change securely.
        """
        try:
            tx = self.wallet.send_to(
                to_address,
                amount_satoshi,
                account_id=account_id,
                fee_rate=fee_rate,
                subtract_fee=subtract_fee
            )
            logging.info(f"Sent {amount_satoshi} satoshis from account {account_id} to {to_address}, TXID: {tx.txid}")
            return tx.txid
        except Exception as e:
            logging.error(f"Error sending transaction: {e}")
            return None

    def get_transactions(self, account_id, include_new=True):
        """
        List transactions for an account.
        """
        txs = self.wallet.transactions(account_id=account_id, include_new=include_new)
        return txs

    def send_all_balance(self, account_id, to_address, fee_rate='fastest'):
        """
        Send all balance from an account (minus fee) to a destination.
        """
        balance = self.get_account_balance(account_id)
        if balance <= 0:
            logging.warning(f"Account {account_id} has no balance")
            return None
        return self.send(account_id, to_address, balance, fee_rate=fee_rate, subtract_fee=True)
