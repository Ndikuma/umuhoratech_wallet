import logging
import threading
from decimal import Decimal
from bitcoinlib.wallets import Wallet, WalletError
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import Key, Address
from bitcoinlib.services.services import Service
from bitcoinlib.encoding import pubkeyhash_to_addr
from bitcoinlib.networks import Network
import time
import base58
import binascii
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BitcoinWalletManager:
    def __init__(self, wallet_name, network='testnet'):
        self.wallet_name = wallet_name
        self.network = network
        self.lock = threading.RLock()
        self.wallet = None
        self.service = Service(network=network)

    # ------------------- WALLET CREATION & RECOVERY -------------------
    def create_wallet_with_mnemonic(self, wallet_name, mnemonic=None, password=None):
        """Create master wallet with optional mnemonic (24-word seed)"""
        with self.lock:
            if not mnemonic:
                mnemonic = Mnemonic().generate()
                logger.info(f"Generated new mnemonic: {mnemonic}")
            self.wallet = Wallet.create(
                wallet_name,
                keys=mnemonic,
                network=self.network,
                witness_type='segwit'
            )
            self.wallet.scan()
            return {
                'wallet_name': wallet_name,
                'mnemonic': mnemonic,
                'address': self.wallet.get_key().address,
                'balance': self.convert_to_btc(self.wallet.balance()['total'])
            }

    def recover_wallet_from_mnemonic(self, wallet_name, mnemonic, password=None):
        """Recover master wallet from mnemonic"""
        with self.lock:
            self.wallet = Wallet.create(
                wallet_name,
                keys=mnemonic,
                network=self.network,
                witness_type='segwit'
            )
            self.wallet.scan()
            return {
                'wallet_name': wallet_name,
                'address': self.wallet.get_key().address,
                'balance': self.convert_to_btc(self.wallet.balance()['total'])
            }

    def recover_wallet_from_public_key(self, wallet_name, public_key):
        """Recover watch-only wallet using public key"""
        with self.lock:
            self.wallet = Wallet.create(
                wallet_name,
                keys=public_key,
                network=self.network,
                witness_type='segwit'
            )
            self.wallet.scan()
            return {
                'wallet_name': wallet_name,
                'address': self.wallet.get_key().address,
                'balance': self.convert_to_btc(self.wallet.balance()['total'])
            }

    def create_multisig_wallet(self, wallet_name, public_keys, signatures_required):
        """Create multisig wallet with public keys and signatures required"""
        with self.lock:
            self.wallet = Wallet.create(
                wallet_name,
                keys=public_keys,
                sigs_required=signatures_required,
                network=self.network,
                witness_type='segwit'
            )
            self.wallet.scan()
            return {
                'wallet_name': wallet_name,
                'address': self.wallet.get_key().address,
                'balance': self.convert_to_btc(self.wallet.balance()['total'])
            }

    def import_private_key(self, wallet_name, private_key):
        """Import wallet from private key"""
        with self.lock:
            self.wallet = Wallet.create(
                wallet_name,
                keys=private_key,
                network=self.network,
                witness_type='segwit'
            )
            self.wallet.scan()
            return {
                'wallet_name': wallet_name,
                'address': self.wallet.get_key().address,
                'balance': self.convert_to_btc(self.wallet.balance()['total'])
            }

    # ------------------- ACCOUNT CREATION & MANAGEMENT -------------------
    def create_account(self, account_id, account_index=None):
        """Create user account with deterministic address"""
        with self.lock:
            if not self.wallet:
                raise WalletError("Master wallet not initialized")
            account_index = account_index or self.wallet.accounts_count()
            account = self.wallet.new_account(account_id)
            account_balance = account.balance()
            return {
                'id': account.id,
                'key_type': account.key_type,
                'network': account.network,
                'is_private': account.is_private,
                'name': account_id,
                'key_public': account.key_public,
                'account_id': account.account_id,
                'parent_id': account.parent_id,
                'depth': account.depth,
                'change': account.change,
                'address_index': account.address_index,
                'address': account.address,
                'encoding': account.encoding,
                'path': account.path,
                'balance': self.convert_to_btc(account_balance['total'])
            }

    def get_account(self, account_id):
        """Retrieve account info by account_id"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return {
                'id': account.id,
                'key_type': account.key_type,
                'network': account.network,
                'is_private': account.is_private,
                'name': account_id,
                'key_public': account.key_public,
                'account_id': account.account_id,
                'parent_id': account.parent_id,
                'depth': account.depth,
                'change': account.change,
                'address_index': account.address_index,
                'address': account.address,
                'encoding': account.encoding,
                'path': account.path,
                'balance': self.convert_to_btc(account.balance()['total'])
            }

    def list_accounts(self):
        """List all accounts in the wallet"""
        with self.lock:
            accounts = self.wallet.accounts()
            return [{
                'name': acc.name,
                'address': acc.address,
                'balance': self.convert_to_btc(acc.balance()['total']),
                'account_id': acc.account_id
            } for acc in accounts]

    def get_account_by_address(self, address):
        """Get account details by address"""
        with self.lock:
            accounts = self.wallet.accounts()
            for acc in accounts:
                if acc.address == address:
                    return {
                        'name': acc.name,
                        'address': acc.address,
                        'balance': self.convert_to_btc(acc.balance()['total']),
                        'account_id': acc.account_id
                    }
            return None

    def delete_account(self, account_id):
        """Delete an account by account_id"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            if account:
                self.wallet.delete_account(account.account_id)
                logger.info(f"Account {account_id} deleted")
                return True
            return False

    # ------------------- ADDRESS MANAGEMENT -------------------
    def generate_new_address(self, account_id, change=False):
        """Generate new address for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            key = account.key_new(change=change)
            return key.address

    def list_addresses(self, account_id):
        """List all addresses for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            keys = account.keys()
            return [key.address for key in keys]

    def get_unused_address(self, account_id):
        """Get unused address for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.key_new_unused().address

    def validate_address(self, address):
        """Validate a Bitcoin address"""
        with self.lock:
            try:
                Address(address, network=self.network)
                return True
            except Exception:
                return False

    def get_address_balance(self, address):
        """Get balance for a specific address"""
        with self.lock:
            balance = self.service.getbalance(address)
            return {'address': address, 'balance': self.convert_to_btc(balance)}

    def generate_batch_addresses(self, account_id, count):
        """Generate multiple addresses at once"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [account.key_new().address for _ in range(count)]

    def convert_address_format(self, address, to_format='segwit'):
        """Convert address between formats (legacy, p2sh, segwit)"""
        with self.lock:
            addr = Address(address, network=self.network)
            if to_format == 'segwit':
                return addr.as_segwit()
            elif to_format == 'p2sh':
                return addr.as_p2sh()
            elif to_format == 'legacy':
                return addr.as_p2pkh()
            raise ValueError("Invalid address format")

    def get_address_type(self, address):
        """Get address type (legacy, p2sh, segwit)"""
        with self.lock:
            addr = Address(address, network=self.network)
            return addr.witness_type or 'legacy'

    def get_address_script_type(self, address):
        """Get script type for an address"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.script_type

    def get_address_public_key(self, address):
        """Get public key for an address"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.public_hex

    # ------------------- UTXO ANALYSIS -------------------
    def analyze_utxos(self, account_id):
        """Analyze UTXOs for given account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = account.utxos()
            analysis = {
                'total_count': len(utxos),
                'dust_utxos': [],
                'small_utxos': [],
                'medium_utxos': [],
                'large_utxos': [],
                'total_value': 0
            }
            for utxo in utxos:
                value = utxo['value']
                analysis['total_value'] += value
                if value < 10000:
                    analysis['dust_utxos'].append(utxo)
                elif value < 100000:
                    analysis['small_utxos'].append(utxo)
                elif value < 1000000:
                    analysis['medium_utxos'].append(utxo)
                else:
                    analysis['large_utxos'].append(utxo)
            analysis['total_value_btc'] = self.convert_to_btc(analysis['total_value'])
            return analysis

    def get_utxos_by_address(self, address):
        """Get UTXOs for a specific address"""
        with self.lock:
            return self.service.getutxos(address)

    def consolidate_utxos(self, account_id, min_utxo_value=10000):
        """Consolidate small UTXOs into a single output"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = [u for u in account.utxos() if u['value'] >= min_utxo_value]
            if not utxos:
                return None
            total_value = sum(u['value'] for u in utxos)
            fee = self.estimate_fee(len(utxos), 1)
            outputs = [{'address': account.address, 'value': total_value - fee}]
            tx = account.wallet.send(outputs, input_arr=utxos, fee=fee, broadcast=False)
            return tx

    def select_utxos(self, account_id, amount):
        """Select UTXOs to cover a specific amount"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = sorted(account.utxos(), key=lambda x: x['value'], reverse=True)
            selected = []
            total = 0
            for utxo in utxos:
                selected.append(utxo)
                total += utxo['value']
                if total >= amount:
                    return selected
            return []

    # ------------------- TRANSACTION CREATION -------------------
    def create_tx(self, account_id, recipients, fee=None):
        """Create transaction for account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            total_amount = sum(r['value'] for r in recipients)
            utxos = account.utxos()
            selected_utxos = []
            selected_amount = 0
            for utxo in sorted(utxos, key=lambda x: x['value'], reverse=True):
                selected_utxos.append(utxo)
                selected_amount += utxo['value']
                if selected_amount >= total_amount + (fee or 0):
                    break
            if selected_amount < total_amount + (fee or 0):
                logger.error("Insufficient funds for transaction")
                return None
            change_amount = selected_amount - total_amount - (fee or 0)
            outputs = [{'address': r['address'], 'value': r['value']} for r in recipients]
            if change_amount > 546:
                outputs.append({'address': account.address, 'value': change_amount})
            tx = account.wallet.send(outputs, input_arr=selected_utxos, fee=fee, broadcast=False)
            return tx

    def broadcast_tx(self, tx):
        """Broadcast a prepared transaction"""
        with self.lock:
            result = self.service.sendrawtransaction(tx.raw_hex())
            self.wallet.scan()
            return result

    def create_multisig_tx(self, account_id, recipients, cosigners, fee=None):
        """Create multisig transaction"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            total_amount = sum(r['value'] for r in recipients)
            utxos = account.utxos()
            selected_utxos = []
            selected_amount = 0
            for utxo in sorted(utxos, key=lambda x: x['value'], reverse=True):
                selected_utxos.append(utxo)
                selected_amount += utxo['value']
                if selected_amount >= total_amount + (fee or 0):
                    break
            if selected_amount < total_amount + (fee or 0):
                logger.error("Insufficient funds for multisig transaction")
                return None
            outputs = [{'address': r['address'], 'value': r['value']} for r in recipients]
            tx = account.wallet.send(outputs, input_arr=selected_utxos, fee=fee, broadcast=False, cosigners=cosigners)
            return tx

    def sign_transaction(self, tx, private_key):
        """Sign transaction with private key"""
        with self.lock:
            tx.sign(private_key)
            return tx

    def verify_transaction(self, tx):
        """Verify transaction signatures"""
        with self.lock:
            return tx.verify()

    def create_timelock_tx(self, account_id, recipient, amount, locktime):
        """Create timelocked transaction"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            outputs = [{'address': recipient, 'value': amount}]
            tx = account.wallet.send(outputs, locktime=locktime, broadcast=False)
            return tx

    def create_rbf_tx(self, account_id, recipients, sequence=0xFFFFFFFE):
        """Create Replace-By-Fee transaction"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            total_amount = sum(r['value'] for r in recipients)
            utxos = account.utxos()
            selected_utxos = []
            selected_amount = 0
            for utxo in sorted(utxos, key=lambda x: x['value'], reverse=True):
                selected_utxos.append(utxo)
                selected_amount += utxo['value']
                if selected_amount >= total_amount:
                    break
            if selected_amount < total_amount:
                logger.error("Insufficient funds for RBF transaction")
                return None
            outputs = [{'address': r['address'], 'value': r['value']} for r in recipients]
            tx = account.wallet.send(outputs, input_arr=selected_utxos, sequence=sequence, broadcast=False)
            return tx

    def create_op_return_tx(self, account_id, data, fee=None):
        """Create transaction with OP_RETURN data"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            data_bytes = data.encode('utf-8')
            if len(data_bytes) > 80:
                raise ValueError("OP_RETURN data exceeds 80 bytes")
            outputs = [{'address': None, 'value': 0, 'script': f'6a{len(data_bytes):02x}{data_bytes.hex()}'}]
            tx = account.wallet.send(outputs, fee=fee, broadcast=False)
            return tx

    def list_transactions(self, account_id, limit=10):
        """List recent transactions for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.transactions(limit=limit)

    def get_transaction(self, txid):
        """Get transaction details by TXID"""
        with self.lock:
            return self.service.gettransaction(txid)

    def get_transaction_confirmations(self, txid):
        """Get number of confirmations for a transaction"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return tx.get('confirmations', 0)

    def batch_send(self, account_id, recipient_list, fee=None):
        """Send multiple transactions in batch"""
        with self.lock:
            transactions = []
            for recipients in recipient_list:
                tx = self.create_tx(account_id, recipients, fee)
                if tx:
                    transactions.append(tx)
            return transactions

    # ------------------- FEE ESTIMATION -------------------
    def estimate_fee(self, input_count, output_count, fee_per_kb=None):
        """Estimate transaction fee based on inputs and outputs"""
        with self.lock:
            if not fee_per_kb:
                fee_per_kb = self.service.estimatefee(6)
            tx_size = (input_count * 148 + output_count * 34 + 10)
            return int((tx_size / 1000) * fee_per_kb)

    def get_current_fee_rates(self):
        """Get current network fee rates"""
        with self.lock:
            return {
                'low': self.service.estimatefee(12),
                'medium': self.service.estimatefee(6),
                'high': self.service.estimatefee(2)
            }

    def estimate_tx_size(self, input_count, output_count):
        """Estimate transaction size in bytes"""
        with self.lock:
            return input_count * 148 + output_count * 34 + 10

    # ------------------- SECURITY -------------------
    def encrypt_wallet(self, password):
        """Encrypt wallet with password"""
        with self.lock:
            self.wallet.encrypt(password)
            logger.info("Wallet encrypted")
            return True

    def decrypt_wallet(self, password):
        """Decrypt wallet with password"""
        with self.lock:
            self.wallet.decrypt(password)
            logger.info("Wallet decrypted")
            return True

    def change_password(self, old_password, new_password):
        """Change wallet encryption password"""
        with self.lock:
            self.wallet.decrypt(old_password)
            self.wallet.encrypt(new_password)
            logger.info("Wallet password changed")
            return True

    def lock_wallet(self):
        """Lock the wallet"""
        with self.lock:
            self.wallet.lock()
            logger.info("Wallet locked")
            return True

    def unlock_wallet(self, password):
        """Unlock the wallet"""
        with self.lock:
            self.wallet.unlock(password)
            logger.info("Wallet unlocked")
            return True

    def generate_key_pair(self):
        """Generate new key pair"""
        with self.lock:
            key = Key(network=self.network)
            return {
                'public_key': key.public_hex,
                'private_key': key.wif if key.is_private else None,
                'address': key.address
            }

    def verify_message(self, address, message, signature):
        """Verify signed message"""
        with self.lock:
            key = Key(address=address, network=self.network)
            return key.verify_message(message.encode('utf-8'), signature)

    def sign_message(self, address, message):
        """Sign message with address's private key"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            if not key.is_private:
                raise ValueError("Private key not available")
            return key.sign_message(message.encode('utf-8'))

    # ------------------- BLOCKCHAIN QUERIES -------------------
    def get_block_info(self, block_height):
        """Get information about a specific block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            return self.service.getblock(block_hash)

    def get_block_count(self):
        """Get current block count"""
        with self.lock:
            return self.service.blockcount()

    def get_difficulty(self):
        """Get current network difficulty"""
        with self.lock:
            return self.service.getdifficulty()

    def get_mempool_info(self):
        """Get mempool information"""
        with self.lock:
            return self.service.getmempoolinfo()

    def get_raw_transaction(self, txid):
        """Get raw transaction hex"""
        with self.lock:
            return self.service.getrawtransaction(txid)

    def decode_raw_transaction(self, raw_tx):
        """Decode raw transaction"""
        with self.lock:
            return self.service.decoderawtransaction(raw_tx)

    def get_mining_info(self):
        """Get mining information"""
        with self.lock:
            return self.service.getmininginfo()

    def get_network_hashrate(self):
        """Get network hashrate"""
        with self.lock:
            return self.service.getnetworkhashps()

    def get_chain_tips(self):
        """Get chain tips"""
        with self.lock:
            return self.service.getchaintips()

    def get_best_block_hash(self):
        """Get best block hash"""
        with self.lock:
            return self.service.getbestblockhash()

    def get_block_header(self, block_hash):
        """Get block header"""
        with self.lock:
            return self.service.getblockheader(block_hash)

    def get_block_stats(self, block_height):
        """Get block statistics"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            return self.service.getblockstats(block_hash)

    def get_tx_out(self, txid, n):
        """Get transaction output details"""
        with self.lock:
            return self.service.gettxout(txid, n)

    def get_tx_out_proof(self, txids):
        """Get proof of transaction inclusion"""
        with self.lock:
            return self.service.gettxoutproof(txids)

    def verify_tx_out_proof(self, proof):
        """Verify transaction output proof"""
        with self.lock:
            return self.service.verifytxoutproof(proof)

    def get_mempool_entry(self, txid):
        """Get mempool entry for a transaction"""
        with self.lock:
            return self.service.getmempoolentry(txid)

    def get_mempool_ancestors(self, txid):
        """Get mempool ancestors for a transaction"""
        with self.lock:
            return self.service.getmempoolancestors(txid)

    def get_mempool_descendants(self, txid):
        """Get mempool descendants for a transaction"""
        with self.lock:
            return self.service.getmempoolsdescendants(txid)

    # ------------------- UTILITY -------------------
    def get_balance(self):
        """Get total wallet balance"""
        with self.lock:
            balance = self.wallet.balance()
            return {
                'total': self.convert_to_btc(balance['total']),
                'confirmed': self.convert_to_btc(balance.get('confirmed', 0)),
                'unconfirmed': self.convert_to_btc(balance.get('unconfirmed', 0))
            }

    def convert_to_btc(self, satoshis):
        """Convert satoshis to BTC"""
        return satoshis / 100_000_000

    def convert_to_satoshis(self, btc):
        """Convert BTC to satoshis"""
        return int(btc * 100_000_000)

    def get_wallet_info(self):
        """Get comprehensive wallet information"""
        with self.lock:
            return {
                'wallet_name': self.wallet_name,
                'network': self.network,
                'balance': self.get_balance(),
                'account_count': self.wallet.accounts_count(),
                'address_count': len(self.wallet.keys()),
                'last_updated': datetime.now().isoformat()
            }

    def get_network_info(self):
        """Get network information"""
        with self.lock:
            return {
                'network': self.network,
                'block_height': self.service.blockcount(),
                'difficulty': self.service.getdifficulty(),
                'network_hashrate': self.service.getnetworkhashps()
            }

    def sweep_funds(self, account_id, destination):
        """Sweep all funds to destination address"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = account.utxos()
            total_value = sum(u['value'] for u in utxos)
            fee = self.estimate_fee(len(utxos), 1)
            outputs = [{'address': destination, 'value': total_value - fee}]
            tx = account.wallet.send(outputs, input_arr=utxos, fee=fee, broadcast=False)
            return tx

    def monitor_transactions(self, account_id, interval=60):
        """Monitor account for new transactions"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            last_tx_count = len(account.transactions())
            while True:
                time.sleep(interval)
                self.wallet.scan()
                current_txs = account.transactions()
                if len(current_txs) > last_tx_count:
                    new_txs = current_txs[:len(current_txs) - last_tx_count]
                    for tx in new_txs:
                        logger.info(f"New transaction detected: {tx['txid']}")
                    last_tx_count = len(current_txs)

    def get_key_info(self, address):
        """Get detailed key information"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return {
                'address': key.address,
                'path': key.path,
                'is_private': key.is_private,
                'public_key': key.public_key,
                'wif': key.wif if key.is_private else None
            }

    def get_wallet_keys(self):
        """Get all keys in the wallet"""
        with self.lock:
            keys = self.wallet.keys()
            return [{'address': k.address, 'path': k.path, 'is_private': k.is_private} for k in keys]

    def create_child_key(self, account_id, index):
        """Derive child key at specific index"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            key = account.key_new(index=index)
            return {
                'address': key.address,
                'path': key.path,
                'public_key': key.public_key
            }

    def get_script_pubkey(self, address):
        """Get scriptPubKey for an address"""
        with self.lock:
            addr = Address(address, network=self.network)
            return addr.script_pubkey.hex()

    def create_psbt(self, account_id, recipients):
        """Create Partially Signed Bitcoin Transaction"""
        with self.lock:
            tx = self.create_tx(account_id, recipients)
            if tx:
                return tx.to_psbt()
            return ""

    def combine_psbt(self, psbts):
        """Combine multiple PSBTs"""
        with self.lock:
            return Transaction.combine_psbts(psbts)

    def finalize_psbt(self, psbt):
        """Finalize a PSBT"""
        with self.lock:
            tx = Transaction.from_psbt(psbt)
            tx.finalize()
            return tx

    def decode_psbt(self, psbt):
        """Decode a PSBT"""
        with self.lock:
            return Transaction.parse_psbt(psbt)

    def is_valid_wif(self, wif):
        """Check if WIF private key is valid"""
        with self.lock:
            try:
                Key(wif, network=self.network)
                return True
            except Exception:
                return False

    def public_key_to_address(self, public_key):
        """Convert public key to address"""
        with self.lock:
            key = Key(public_key, network=self.network)
            return key.address

    def base58_encode(self, data):
        """Encode data to base58"""
        with self.lock:
            return base58.b58encode(data.encode()).decode()

    def base58_decode(self, data):
        """Decode base58 data"""
        with self.lock:
            return base58.b58decode(data).decode()

    def get_tx_inputs(self, tx):
        """Get inputs of a transaction"""
        with self.lock:
            return [{'txid': inp.txid, 'vout': inp.vout, 'value': inp.value} for inp in tx.inputs]

    def get_tx_outputs(self, tx):
        """Get outputs of a transaction"""
        with self.lock:
            return [{'address': out.address, 'value': out.value} for out in tx.outputs]

    def calculate_tx_fee(self, tx):
        """Calculate transaction fee"""
        with self.lock:
            input_value = sum(inp.value for inp in tx.inputs)
            output_value = sum(out.value for out in tx.outputs)
            return input_value - output_value

    def get_tx_size(self, tx):
        """Get transaction size in bytes"""
        with self.lock:
            return len(tx.raw_hex()) // 2

    def get_tx_vsize(self, tx):
        """Get transaction virtual size"""
        with self.lock:
            return tx.vsize

    def is_rbf_enabled(self, tx):
        """Check if transaction supports RBF"""
        with self.lock:
            return any(inp.sequence < 0xFFFFFFFE for inp in tx.inputs)

    def get_peer_info(self):
        """Get information about connected peers"""
        with self.lock:
            return self.service.getpeerinfo()

    def get_network_details(self):
        """Get detailed network information"""
        with self.lock:
            return self.service.getnetworkinfo()

    def get_mempool_size(self):
        """Get number of transactions in mempool"""
        with self.lock:
            return self.service.getmempoolinfo()['size']

    def get_mempool_bytes(self):
        """Get total bytes of transactions in mempool"""
        with self.lock:
            return self.service.getmempoolinfo()['bytes']

    def scan_wallet(self):
        """Scan wallet for updates"""
        with self.lock:
            self.wallet.scan()
            return True

    def rescan_blockchain(self, start_height=0):
        """Rescan blockchain from a specific height"""
        with self.lock:
            self.wallet.scan(start_height=start_height)
            return True

    def get_wallet_utxos(self):
        """Get all UTXOs for the wallet"""
        with self.lock:
            return self.wallet.utxos()

    def get_account_utxos(self, account_id):
        """Get UTXOs for a specific account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.utxos()

    def batch_sign_transactions(self, transactions, private_keys):
        """Sign multiple transactions in batch"""
        with self.lock:
            signed_txs = []
            for tx in transactions:
                for key in private_keys:
                    tx = self.sign_transaction(tx, key)
                signed_txs.append(tx)
            return signed_txs

    def batch_broadcast_transactions(self, transactions):
        """Broadcast multiple transactions in batch"""
        with self.lock:
            results = []
            for tx in transactions:
                result = self.broadcast_tx(tx)
                results.append(result)
            return results

    def import_public_key(self, account_id, public_key):
        """Import public key to an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            key = Key(public_key, network=self.network)
            account.import_key(key)
            return key.address

    def derive_child_public_key(self, public_key, index):
        """Derive child public key"""
        with self.lock:
            key = Key(public_key, network=self.network)
            child_key = key.child(index)
            return child_key.public_hex

    def get_key_path(self, address):
        """Get derivation path for an address"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.path

    def monitor_address(self, address, interval=60):
        """Monitor address for new transactions"""
        with self.lock:
            last_txs = self.service.gettransactions(address, limit=10)
            last_tx_count = len(last_txs)
            while True:
                time.sleep(interval)
                current_txs = self.service.gettransactions(address, limit=10)
                if len(current_txs) > last_tx_count:
                    new_txs = current_txs[:len(current_txs) - last_tx_count]
                    for tx in new_txs:
                        logger.info(f"New transaction for address {address}: {tx['txid']}")
                    last_tx_count = len(current_txs)

    def get_address_transactions(self, address, limit=10):
        """Get transactions for a specific address"""
        with self.lock:
            return self.service.gettransactions(address, limit=limit)

    def get_block_by_hash(self, block_hash):
        """Get block by hash"""
        with self.lock:
            return self.service.getblock(block_hash)

    def get_block_transactions(self, block_hash):
        """Get transaction IDs in a block"""
        with self.lock:
            block = self.service.getblock(block_hash)
            return block.get('tx', [])

    def get_block_time(self, block_height):
        """Get block timestamp"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['time']

    def get_block_merkle_root(self, block_height):
        """Get block merkle root"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['merkleroot']

    def get_current_time(self):
        """Get current time in ISO format"""
        return datetime.now().isoformat()

    def generate_random_mnemonic(self):
        """Generate random mnemonic"""
        with self.lock:
            return Mnemonic().generate()

    def validate_mnemonic(self, mnemonic):
        """Validate mnemonic phrase"""
        with self.lock:
            return Mnemonic().check(mnemonic)

    def mnemonic_to_seed(self, mnemonic, password=''):
        """Convert mnemonic to seed"""
        with self.lock:
            return Mnemonic().to_seed(mnemonic, password).hex()

    def seed_to_mnemonic(self, seed):
        """Convert seed to mnemonic"""
        with self.lock:
            return Mnemonic().to_mnemonic(binascii.unhexlify(seed))

    def get_wallet_id(self):
        """Get wallet ID"""
        with self.lock:
            return self.wallet.wallet_id

    def get_wallet_type(self):
        """Get wallet type"""
        with self.lock:
            return self.wallet.type

    def get_wallet_network(self):
        """Get wallet network"""
        with self.lock:
            return self.wallet.network.name

    def get_wallet_balance_confirmed(self):
        """Get confirmed wallet balance in BTC"""
        with self.lock:
            return self.convert_to_btc(self.wallet.balance()['confirmed'])

    def get_wallet_balance_unconfirmed(self):
        """Get unconfirmed wallet balance in BTC"""
        with self.lock:
            return self.convert_to_btc(self.wallet.balance()['unconfirmed'])

    def get_address_count(self):
        """Get total number of addresses in wallet"""
        with self.lock:
            return len(self.wallet.keys())

    def get_account_count(self):
        """Get total number of accounts in wallet"""
        with self.lock:
            return self.wallet.accounts_count()

    def is_wallet_encrypted(self):
        """Check if wallet is encrypted"""
        with self.lock:
            return self.wallet.is_encrypted

    def is_wallet_locked(self):
        """Check if wallet is locked"""
        with self.lock:
            return self.wallet.is_locked

    def get_wallet_owner(self):
        """Get wallet owner"""
        with self.lock:
            return self.wallet.owner or "Unknown"

    def set_wallet_owner(self, owner):
        """Set wallet owner"""
        with self.lock:
            self.wallet.owner = owner
            return True

    def get_wallet_creation_time(self):
        """Get wallet creation time"""
        with self.lock:
            return self.wallet.date_created.isoformat() if self.wallet.date_created else ""

    def get_wallet_last_updated(self):
        """Get wallet last updated time"""
        with self.lock:
            return self.wallet.date_updated.isoformat() if self.wallet.date_updated else ""

    def get_wallet_key_count(self):
        """Get total number of keys in wallet"""
        with self.lock:
            return len(self.wallet.keys())

    def get_wallet_transaction_count(self):
        """Get total number of transactions in wallet"""
        with self.lock:
            return len(self.wallet.transactions())

    def get_wallet_utxo_count(self):
        """Get total number of UTXOs in wallet"""
        with self.lock:
            return len(self.wallet.utxos())

    def get_wallet_address_list(self):
        """Get list of all addresses in wallet"""
        with self.lock:
            return [k.address for k in self.wallet.keys()]

    def get_wallet_public_keys(self):
        """Get list of all public keys in wallet"""
        with self.lock:
            return [k.public_hex for k in self.wallet.keys()]

    def get_wallet_private_keys(self):
        """Get list of all private keys in wallet"""
        with self.lock:
            return [k.wif for k in self.wallet.keys() if k.is_private]

    def get_account_balance(self, account_id):
        """Get balance for a specific account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return self.convert_to_btc(account.balance()['total'])

    def get_account_address_count(self, account_id):
        """Get number of addresses in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return len(account.keys())

    def get_account_transaction_count(self, account_id):
        """Get number of transactions in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return len(account.transactions())

    def get_account_utxo_count(self, account_id):
        """Get number of UTXOs in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return len(account.utxos())

    def get_account_public_keys(self, account_id):
        """Get list of public keys in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.public_hex for k in account.keys()]

    def get_account_private_keys(self, account_id):
        """Get list of private keys in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.wif for k in account.keys() if k.is_private]

    def get_account_key_paths(self, account_id):
        """Get derivation paths for all keys in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.path for k in account.keys()]

    def get_account_first_address(self, account_id):
        """Get first address in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            keys = account.keys()
            return keys[0].address if keys else ""

    def get_account_last_address(self, account_id):
        """Get last address in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            keys = account.keys()
            return keys[-1].address if keys else ""

    def get_account_unused_addresses(self, account_id):
        """Get all unused addresses in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.address for k in account.keys() if not k.used]

    def get_account_used_addresses(self, account_id):
        """Get all used addresses in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.address for k in account.keys() if k.used]

    def get_account_balance_confirmed(self, account_id):
        """Get confirmed balance for an account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return self.convert_to_btc(account.balance()['confirmed'])

    def get_account_balance_unconfirmed(self, account_id):
        """Get unconfirmed balance for an account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return self.convert_to_btc(account.balance()['unconfirmed'])

    def get_account_creation_time(self, account_id):
        """Get account creation time"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.date_created.isoformat() if account.date_created else ""

    def get_account_last_updated(self, account_id):
        """Get account last updated time"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.date_updated.isoformat() if account.date_updated else ""

    def get_account_key_count(self, account_id):
        """Get number of keys in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return len(account.keys())

    def get_account_id_value(self, account_id):
        """Get account ID value"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.account_id

    def get_account_depth(self, account_id):
        """Get account derivation depth"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.depth

    def get_account_parent_id(self, account_id):
        """Get account parent ID"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.parent_id

    def get_account_key_type(self, account_id):
        """Get account key type"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.key_type

    def get_account_encoding(self, account_id):
        """Get account address encoding"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.encoding

    def is_account_private(self, account_id):
        """Check if account has private keys"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.is_private

    def get_account_path(self, account_id):
        """Get account derivation path"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.path

    def get_account_address_index(self, account_id):
        """Get account address index"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.address_index

    def get_account_change(self, account_id):
        """Get account change index"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return account.change

    def get_address_wif(self, address):
        """Get WIF private key for an address"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.wif if key.is_private else None

    def get_address_path(self, address):
        """Get derivation path for an address"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.path

    def is_address_used(self, address):
        """Check if an address has been used"""
        with self.lock:
            key = self.wallet.key_for_address(address)
            return key.used

    def get_address_balance_confirmed(self, address):
        """Get confirmed balance for an address"""
        with self.lock:
            balance = self.service.getbalance(address)
            return self.convert_to_btc(balance.get('confirmed', 0))

    def get_address_balance_unconfirmed(self, address):
        """Get unconfirmed balance for an address"""
        with self.lock:
            balance = self.service.getbalance(address)
            return self.convert_to_btc(balance.get('unconfirmed', 0))

    def get_address_utxos(self, address):
        """Get UTXOs for an address"""
        with self.lock:
            return self.service.getutxos(address)

    def get_address_transaction_count(self, address):
        """Get number of transactions for an address"""
        with self.lock:
            return len(self.service.gettransactions(address))

    def get_address_first_transaction(self, address):
        """Get first transaction for an address"""
        with self.lock:
            txs = self.service.gettransactions(address, limit=1)
            return txs[0] if txs else {}

    def get_address_last_transaction(self, address):
        """Get last transaction for an address"""
        with self.lock:
            txs = self.service.gettransactions(address)
            return txs[-1] if txs else {}

    def get_address_received(self, address):
        """Get total received amount for an address in BTC"""
        with self.lock:
            utxos = self.service.getutxos(address)
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'receive'))

    def get_address_spent(self, address):
        """Get total spent amount for an address in BTC"""
        with self.lock:
            utxos = self.service.getutxos(address)
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'spend'))

    def get_transaction_fee(self, txid):
        """Get fee for a transaction in BTC"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return self.convert_to_btc(tx.get('fee', 0))

    def get_transaction_time(self, txid):
        """Get timestamp of a transaction"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return datetime.fromtimestamp(tx['time']).isoformat() if tx.get('time') else ""

    def get_transaction_block_height(self, txid):
        """Get block height of a transaction"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return tx.get('blockheight', 0)

    def get_transaction_block_hash(self, txid):
        """Get block hash of a transaction"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return tx.get('blockhash', "")

    def get_transaction_inputs(self, txid):
        """Get inputs for a transaction"""
        with self.lock:
            tx = self.service.getrawtransaction(txid, True)
            return tx.get('vin', [])

    def get_transaction_outputs(self, txid):
        """Get outputs for a transaction"""
        with self.lock:
            tx = self.service.getrawtransaction(txid, True)
            return tx.get('vout', [])

    def get_transaction_amount(self, txid):
        """Get total output amount for a transaction in BTC"""
        with self.lock:
            tx = self.service.getrawtransaction(txid, True)
            return self.convert_to_btc(sum(out['value'] * 100_000_000 for out in tx.get('vout', [])))

    def get_transaction_size(self, txid):
        """Get size of a transaction in bytes"""
        with self.lock:
            tx = self.service.getrawtransaction(txid)
            return len(tx) // 2

    def get_transaction_vsize(self, txid):
        """Get virtual size of a transaction"""
        with self.lock:
            tx = Transaction.parse(self.service.getrawtransaction(txid))
            return tx.vsize

    def is_transaction_confirmed(self, txid):
        """Check if a transaction is confirmed"""
        with self.lock:
            tx = self.service.gettransaction(txid)
            return tx.get('confirmations', 0) > 0

    def get_block_confirmations(self, block_height):
        """Get number of confirmations for a block"""
        with self.lock:
            current_height = self.service.blockcount()
            return max(0, current_height - block_height + 1)

    def get_block_difficulty(self, block_height):
        """Get difficulty of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['difficulty']

    def get_block_size(self, block_height):
        """Get size of a block in bytes"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['size']

    def get_block_weight(self, block_height):
        """Get weight of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['weight']

    def get_block_version(self, block_height):
        """Get version of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['version']

    def get_block_nonce(self, block_height):
        """Get nonce of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['nonce']

    def get_block_bits(self, block_height):
        """Get bits of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['bits']

    def get_block_chainwork(self, block_height):
        """Get chainwork of a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['chainwork']

    def get_block_previous_hash(self, block_height):
        """Get previous block hash"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block['previousblockhash']

    def get_block_next_hash(self, block_height):
        """Get next block hash"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return block.get('nextblockhash', "")

    def get_block_transaction_count(self, block_height):
        """Get number of transactions in a block"""
        with self.lock:
            block_hash = self.service.getblockhash(block_height)
            block = self.service.getblock(block_hash)
            return len(block['tx'])

    def get_mempool_min_fee(self):
        """Get minimum fee for mempool acceptance in BTC/kB"""
        with self.lock:
            return self.convert_to_btc(self.service.getmempoolinfo()['minfee'])

    def get_mempool_max_size(self):
        """Get maximum mempool size in bytes"""
        with self.lock:
            return self.service.getmempoolinfo()['maxmempool']

    def get_network_connections(self):
        """Get number of network connections"""
        with self.lock:
            return self.service.getnetworkinfo()['connections']

    def get_network_version(self):
        """Get network protocol version"""
        with self.lock:
            return self.service.getnetworkinfo()['protocolversion']

    def get_network_subversion(self):
        """Get network subversion"""
        with self.lock:
            return self.service.getnetworkinfo()['subversion']

    def get_network_relay_fee(self):
        """Get minimum relay fee in BTC/kB"""
        with self.lock:
            return self.convert_to_btc(self.service.getnetworkinfo()['relayfee'])

    def get_network_local_addresses(self):
        """Get local addresses of the node"""
        with self.lock:
            return self.service.getnetworkinfo()['localaddresses']

    def get_network_time_offset(self):
        """Get network time offset"""
        with self.lock:
            return self.service.getnetworkinfo()['timeoffset']

    def get_peer_addresses(self):
        """Get addresses of connected peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['addr'] for peer in peers]

    def get_peer_versions(self):
        """Get versions of connected peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['version'] for peer in peers]

    def get_peer_subversions(self):
        """Get subversions of connected peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['subver'] for peer in peers]

    def get_peer_connection_times(self):
        """Get connection times of peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['conntime'] for peer in peers]

    def get_peer_bytes_sent(self):
        """Get bytes sent to peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['bytessent'] for peer in peers]

    def get_peer_bytes_received(self):
        """Get bytes received from peers"""
        with self.lock:
            peers = self.service.getpeerinfo()
            return [peer['bytesrecv'] for peer in peers]

    def get_address_first_used(self, address):
        """Get first use timestamp of an address"""
        with self.lock:
            txs = self.service.gettransactions(address, limit=1)
            return txs[0].get('time', 0) if txs else 0

    def get_address_last_used(self, address):
        """Get last use timestamp of an address"""
        with self.lock:
            txs = self.service.gettransactions(address)
            return txs[-1].get('time', 0) if txs else 0

    def get_wallet_first_transaction(self):
        """Get first transaction in wallet"""
        with self.lock:
            txs = self.wallet.transactions(limit=1)
            return txs[0] if txs else {}

    def get_wallet_last_transaction(self):
        """Get last transaction in wallet"""
        with self.lock:
            txs = self.wallet.transactions()
            return txs[-1] if txs else {}

    def get_account_first_transaction(self, account_id):
        """Get first transaction for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            txs = account.transactions(limit=1)
            return txs[0] if txs else {}

    def get_account_last_transaction(self, account_id):
        """Get last transaction for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            txs = account.transactions()
            return txs[-1] if txs else {}

    def get_wallet_received(self):
        """Get total received amount in wallet in BTC"""
        with self.lock:
            utxos = self.wallet.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'receive'))

    def get_wallet_spent(self):
        """Get total spent amount in wallet in BTC"""
        with self.lock:
            utxos = self.wallet.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'spend'))

    def get_account_received(self, account_id):
        """Get total received amount for an account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = account.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'receive'))

    def get_account_spent(self, account_id):
        """Get total spent amount for an account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = account.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'spend'))

    def get_wallet_balance_history(self):
        """Get balance history of wallet"""
        with self.lock:
            txs = self.wallet.transactions()
            history = []
            balance = 0
            for tx in sorted(txs, key=lambda x: x['time']):
                balance_change = sum(out['value'] for out in tx.get('vout', []) if out['address'] in self.get_wallet_address_list())
                balance += balance_change
                history.append({'time': tx['time'], 'balance': self.convert_to_btc(balance)})
            return history

    def get_account_balance_history(self, account_id):
        """Get balance history of an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            txs = account.transactions()
            history = []
            balance = 0
            for tx in sorted(txs, key=lambda x: x['time']):
                balance_change = sum(out['value'] for out in tx.get('vout', []) if out['address'] in self.get_account_addresses(account_id))
                balance += balance_change
                history.append({'time': tx['time'], 'balance': self.convert_to_btc(balance)})
            return history

    def get_account_addresses(self, account_id):
        """Get all addresses for an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [k.address for k in account.keys()]

    def get_wallet_utxo_value(self):
        """Get total UTXO value in wallet in BTC"""
        with self.lock:
            utxos = self.wallet.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos))

    def get_account_utxo_value(self, account_id):
        """Get total UTXO value in account in BTC"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            utxos = account.utxos()
            return self.convert_to_btc(sum(u['value'] for u in utxos))

    def get_wallet_transaction_ids(self):
        """Get all transaction IDs in wallet"""
        with self.lock:
            return [tx['txid'] for tx in self.wallet.transactions()]

    def get_account_transaction_ids(self, account_id):
        """Get all transaction IDs in an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            return [tx['txid'] for tx in account.transactions()]

    def get_wallet_first_address(self):
        """Get first address in wallet"""
        with self.lock:
            keys = self.wallet.keys()
            return keys[0].address if keys else ""

    def get_wallet_last_address(self):
        """Get last address in wallet"""
        with self.lock:
            keys = self.wallet.keys()
            return keys[-1].address if keys else ""

    def get_wallet_unused_addresses(self):
        """Get all unused addresses in wallet"""
        with self.lock:
            return [k.address for k in self.wallet.keys() if not k.used]

    def get_wallet_used_addresses(self):
        """Get all used addresses in wallet"""
        with self.lock:
            return [k.address for k in self.wallet.keys() if k.used]

    def get_wallet_first_used(self):
        """Get first use timestamp of wallet"""
        with self.lock:
            txs = self.wallet.transactions(limit=1)
            return txs[0].get('time', 0) if txs else 0

    def get_wallet_last_used(self):
        """Get last use timestamp of wallet"""
        with self.lock:
            txs = self.wallet.transactions()
            return txs[-1].get('time', 0) if txs else 0

    def get_account_first_used(self, account_id):
        """Get first use timestamp of an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            txs = account.transactions(limit=1)
            return txs[0].get('time', 0) if txs else 0

    def get_account_last_used(self, account_id):
        """Get last use timestamp of an account"""
        with self.lock:
            account = self.wallet.get_account(account_id)
            txs = account.transactions()
            return txs[-1].get('time', 0) if txs else 0

    def get_wallet_balance_confirmed(self):
        """Get confirmed balance of wallet in BTC"""
        with self.lock:
            return self.convert_to_btc(self.wallet.balance()['confirmed'])

    def get_wallet_balance_unconfirmed(self):
        """Get unconfirmed balance of wallet in BTC"""
        with self.lock:
            return self.convert_to_btc(self.wallet.balance()['unconfirmed'])

    def get_wallet_address_balance(self, address):
        """Get balance for a specific address in wallet in BTC"""
        with self.lock:
            return self.convert_to_btc(self.service.getbalance(address))

    def get_wallet_address_utxos(self, address):
        """Get UTXOs for a specific address in wallet"""
        with self.lock:
            return self.service.getutxos(address)

    def get_wallet_address_transactions(self, address, limit=10):
        """Get transactions for a specific address in wallet"""
        with self.lock:
            return self.service.gettransactions(address, limit=limit)

    def get_wallet_address_transaction_count(self, address):
        """Get number of transactions for a specific address in wallet"""
        with self.lock:
            return len(self.service.gettransactions(address))

    def get_wallet_address_first_transaction(self, address):
        """Get first transaction for a specific address in wallet"""
        with self.lock:
            txs = self.service.gettransactions(address, limit=1)
            return txs[0] if txs else {}

    def get_wallet_address_last_transaction(self, address):
        """Get last transaction for a specific address in wallet"""
        with self.lock:
            txs = self.service.gettransactions(address)
            return txs[-1] if txs else {}

    def get_wallet_address_received(self, address):
        """Get total received amount for a specific address in wallet in BTC"""
        with self.lock:
            utxos = self.service.getutxos(address)
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'receive'))

    def get_wallet_address_spent(self, address):
        """Get total spent amount for a specific address in wallet in BTC"""
        with self.lock:
            utxos = self.service.getutxos(address)
            return self.convert_to_btc(sum(u['value'] for u in utxos if u['type'] == 'spend'))

    def get_wallet_address_first_used(self, address):
        """Get first use timestamp of a specific address in wallet"""
        with self.lock:
            txs = self.service.gettransactions(address, limit=1)
            return txs[0].get('time', 0) if txs else 0

    def get_wallet_address_last_used(self, address):
        """Get last use timestamp of a specific address in wallet"""
        with self.lock:
            txs = self.service.gettransactions(address)
            return txs[-1].get('time', 0) if txs else 0