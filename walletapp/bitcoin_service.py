import logging
from decimal import Decimal
from io import BytesIO
import base64
import requests
import qrcode
from bitcoinlib.keys import HDKey
from bitcoinlib.wallets import Wallet, wallet_exists,wallet_create_or_open, WalletError
from bitcoinlib.services.services import Service, ServiceError
from bitcoinlib.transactions import Transaction
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import Key
from bitcoinlib.encoding import to_hexstring
from functools import wraps
from django.conf  import settings
import threading
import json
import time

# Logger
logger = logging.getLogger("wallet")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def to_satoshis(amount):
    """Convert BTC to satoshis"""
    return int(Decimal(amount) * Decimal(1e8))


def to_btc(satoshis):
    """Convert satoshis to BTC"""
    return Decimal(satoshis) / Decimal(1e8)




def get_btc_usd_price():
    """
    Fetch BTC price in USD from CryptoCompare.
    """
    try:
        url = "https://min-api.cryptocompare.com/data/price"
        params = {"fsym": "BTC", "tsyms": "USD"}
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get("USD", 0.0)
    except Exception as e:
        logger.warning(f"Failed to fetch BTC price: {e}")
        return 0.0


def get_fee_rate(priority="halfHour"):
    """
    Get recommended Bitcoin fee rate in sat/vbyte using mempool.space API.
    """
    priority_map = {
        "halfHour": "halfHourFee",
        "hour": "hourFee",
        "fastest": "fastestFee",
        "minimum": "minimumFee"
    }
    
    try:
        url = "https://mempool.space/api/v1/fees/recommended"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        fee_rate = data.get(priority_map.get(priority, "halfHourFee"), 10)
        return fee_rate
    except Exception as e:
        logger.warning(f"Failed to get fee rate from mempool.space: {e}")
        # Fallback to blockchain.info
        try:
            url = "https://blockchain.info/fees?format=json"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if priority == "fastest":
                fee_rate = data["regular"]  # Using regular as fallback for fastest
            else:
                fee_rate = data["regular"]  # Using regular as fallback
            return fee_rate
        except Exception as e2:
            logger.warning(f"Failed to get fee rate from blockchain.info: {e2}")
            return 10  # Final fallback


class BitcoinRPCError(Exception):
    """Custom exception for Bitcoin RPC errors"""
    pass


class TransactionTracker:
    """Class to track transaction status in the network"""
    
    def __init__(self, network="testnet"):
        self.network = network
        self.base_url = f"https://blockstream.info/{'testnet/' if network == 'testnet' else ''}api"
    
    def get_transaction_status(self, txid):
        """Get transaction status from blockchain"""
        try:
            # Try to get transaction details
            url = f"{self.base_url}/tx/{txid}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                tx_data = resp.json()
                confirmations = tx_data.get("status", {}).get("block_height", 0)
                if confirmations > 0:
                    # Get block details for timestamp
                    block_url = f"{self.base_url}/block/{tx_data['status']['block_hash']}"
                    block_resp = requests.get(block_url, timeout=10)
                    block_time = block_resp.json().get("timestamp", int(time.time())) if block_resp.status_code == 200 else int(time.time())
                    
                    return {
                        "confirmed": True,
                        "confirmations": confirmations,
                        "block_height": tx_data["status"]["block_height"],
                        "block_time": block_time,
                        "size": tx_data.get("size", 0),
                        "vsize": tx_data.get("vsize", 0),
                        "fee": tx_data.get("fee", 0),
                        "inputs": [{"txid": inp["txid"], "vout": inp["vout"]} for inp in tx_data.get("vin", [])],
                        "outputs": [{"address": out["scriptpubkey_address"], "value": out["value"]} for out in tx_data.get("vout", [])]
                    }
                else:
                    return {
                        "confirmed": False,
                        "confirmations": 0,
                        "in_mempool": True
                    }
            else:
                # Check if transaction is in mempool
                mempool_url = f"{self.base_url}/mempool"
                mempool_resp = requests.get(mempool_url, timeout=10)
                if mempool_resp.status_code == 200:
                    mempool_txs = mempool_resp.json()
                    if txid in mempool_txs:
                        return {
                            "confirmed": False,
                            "confirmations": 0,
                            "in_mempool": True
                        }
                
                return {
                    "confirmed": False,
                    "confirmations": 0,
                    "in_mempool": False,
                    "error": "Transaction not found"
                }
                
        except Exception as e:
            logger.error(f"Error tracking transaction {txid}: {e}")
            return {
                "confirmed": False,
                "confirmations": 0,
                "in_mempool": False,
                "error": str(e)
            }


class BitcoinService:
    """
    Bitcoin service class for wallet management using bitcoinlib.
    Supports creation, restoration (mnemonic/WIF), balance, addresses, transactions, QR codes.
    """

    def __init__(self, wallet_name=None, fee_address=None, network="testnet"):
        self.wallet_name = wallet_name
        self.wallet = None
        self.fee_address = fee_address
        self.network = network
        self.tracker = TransactionTracker(network)
        # ,db_uri=str(settings.BITCOINLIB_DB)
        if wallet_name and wallet_exists(wallet_name,db_uri=str(settings.BITCOINLIB_DB)):
            try:
                self.wallet = Wallet(wallet_name,db_uri=str(settings.BITCOINLIB_DB))
                # self.wallet.scan()  # Ensure wallet is up to date
                logger.info(f"Wallet '{wallet_name}' loaded successfully")
            except Exception as e:
                logger.error(f"Error loading wallet: {e}")

   
    def create_wallet(self, wallet_name, mnemonic=None):
        self.wallet = wallet_create_or_open(wallet_name, keys=mnemonic, network=self.network,db_uri=str(settings.BITCOINLIB_DB))
        logger.info(f"Wallet {wallet_name} loaded or created.")
        return {"wallet_name": wallet_name, "address": self.wallet.get_key().address}

    def restore_wallet(self, wallet_name, keys):
        self.wallet = wallet_create_or_open(wallet_name, keys=keys, network=self.network)
        logger.info(f"Wallet {wallet_name} restored or loaded.")
        return {"wallet_name": wallet_name, "address": self.wallet.get_key().address}

    def backup_wallet(self):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        key = self.wallet.wif()
        return {"wif": key}

   
    def get_balance(self, include_usd=True):
        """Get wallet balance"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        self.wallet.scan()
        balance_sat = self.wallet.balance()
        balance_btc = to_btc(balance_sat)

        result = {
            "satoshis": int(balance_sat), 
            "btc": float(balance_btc),
        }
        
        if include_usd:
            usd_price = get_btc_usd_price()
            result["usd_value"] = float(balance_btc * Decimal(usd_price))
            result["btc_price_usd"] = float(usd_price)
        
        return result

   
    def get_new_address(self, label=None, change=False):
        """Generate a new receiving address"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        
        key = self.wallet.get_key(change=change)
        return {
            "address": key.address,
        }

   
    def get_utxos(self):
        """Get list of unspent transaction outputs"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        
        utxos = self.wallet.utxos()
        return [{
            "txid": u['txid'],
            "output_n": u['output_n'],
            "value": u['value'],
            "value_btc": float(to_btc(u['value'])),
            "address": u['address'],
            "confirmations": u.get('confirmations', 0),
            "spendable": u.get('spendable', True)
        } for u in utxos]

   
    def send_to_address(self, to_address, amount, broadcast=False):
        """Send BTC to an address"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        tx = self.wallet.send_to(
            to_address,
            to_satoshis(amount),
            broadcast=broadcast  # False = just build (dry run), True = actually send
        )
        
        if broadcast:
            return {
                "txid": tx.txid,
                "amount_btc": float(to_btc(amount)),
                "to_address": to_address,
                "fees": float(to_btc(tx.fee)),
                "tx_hex": tx.as_hex(),
                "from_address": self.wallet.get_key().address,
                "explorer_url": f"https://blockstream.info/{'testnet/' if self.wallet.network.name == 'testnet' else ''}tx/{tx.txid}" if tx.txid else None,
                "message": "Transaction broadcasted successfully"
            }
        else:
            return {
                "tx_hex": tx.as_hex(),
                "fee_btc": float(to_btc(tx.fee)),
                "txid": tx.txid,
                "to_address": to_address,
                "from_address": self.wallet.get_key().address,
                "confirmations": 0,
                "spendable": True,
                "amount_btc": float(to_btc(amount)),
                "message": "Transaction created (not broadcasted)"
            }
    def estimate_sendable_amount(self, total_amount: float) -> dict:
        """
        Estimate the actual sendable amount after network fee.
        total_amount: total satoshis user wants to spend
        Returns dict with:
            - sendable_amount: amount minus fee
            - fee: estimated network fee
        """
        if not self.wallet:
            raise Exception("No wallet loaded")


        # Use wallet's own address for temp tx
        to_address = self.wallet.get_key().address

        # Create a temporary tx for fee estimation
        tx = self.wallet.transaction_create(
            [(to_address, to_satoshis(total_amount))],
        )

        fee_estimate = tx.fee

        # Delete the temporary tx
        # tx.delete()

        # Calculate sendable amount after subtracting fee
        sendable_amount = to_satoshis(total_amount) - fee_estimate
        if sendable_amount < 0:
            sendable_amount = 0  # cannot send negative

        return {
            "sendable_amount": to_btc(sendable_amount),
            "fee": to_btc(fee_estimate)
        }
    def send_with_service_fee(self, to_address, amount_btc, service_fee_percent=0.04,
                          fee_priority="halfHour", dust_limit=546, broadcast=False):
        """
        Send BTC using wallet.send, adding a service fee output.
        Automatically adjusts network fee based on actual transaction size.
        """
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        if amount_btc <= 0:
            raise ValueError("Amount must be positive")
        if not (0 <= service_fee_percent <= 0.1):
            raise ValueError("Service fee percent must be between 0 and 0.1")
        if not self.fee_address:
            raise ValueError("Service fee address not configured")
        if to_address == self.fee_address:
            raise ValueError("Destination address cannot be the service fee address")

        wallet = self.wallet
        amount_satoshi = to_satoshis(amount_btc)
        fee_rate = get_fee_rate(fee_priority)  # sat/vB

        # Calculate service fee in satoshis
        service_fee_satoshi = int(Decimal(str(service_fee_percent)) * amount_satoshi)
        rough_fee = int(200 * fee_rate)
        total_to_cover = amount_satoshi + service_fee_satoshi + rough_fee
        balance = wallet.balance()
        if total_to_cover > balance:
            raise ValueError("Insufficient funds for transaction including service fee and estimated network fee")

        # Select minimal inputs
        selected_inputs = wallet.select_inputs(total_to_cover)
        if not selected_inputs:
            raise ValueError("Insufficient UTXOs for transaction")

        # Build inputs with value from wallet.utxos()
        utxos = {u['txid']: u for u in wallet.utxos()}
        inputs_with_value = []
        total_input = 0
        for inp in selected_inputs:
            key = inp.prev_txid.hex()
            if key not in utxos:
                raise ValueError(f"UTXO not found for input {key}")
            u = utxos[key]
            inputs_with_value.append({
                "txid": u['txid'],
                "output_n": u['output_n'],
                "value": u['value'],
                "address": u['address']
            })
            total_input += u['value']

        # Build initial outputs
        outputs = [(to_address, amount_satoshi)]
        if service_fee_satoshi > dust_limit:
            outputs.append((self.fee_address, service_fee_satoshi))

        # Iteratively adjust fee and change output
        while True:
            tx_tmp = Transaction(network=wallet.network.name)
            for u in inputs_with_value:
                tx_tmp.add_input(u["txid"], u["output_n"], value=u["value"], address=u["address"])
            for addr, amt in outputs:
                tx_tmp.add_output(amt, addr)

            estimated_size = tx_tmp.estimate_size()
            estimated_network_fee = int(estimated_size * fee_rate)

            change_satoshi = total_input - amount_satoshi - service_fee_satoshi - estimated_network_fee
            change_address = wallet.get_key(change=True).address

            # Handle change output
            if change_satoshi <= 0:
                change_satoshi = 0
                outputs = [o for o in outputs if o[0] != change_address]
            else:
                outputs = [o for o in outputs if o[0] != change_address]
                outputs.append((change_address, change_satoshi))

            # Recalculate size after change
            tx_tmp = Transaction(network=wallet.network.name)
            for u in inputs_with_value:
                tx_tmp.add_input(u["txid"], u["output_n"], value=u["value"], address=u["address"])
            for addr, amt in outputs:
                tx_tmp.add_output(amt, addr)

            new_estimated_size = tx_tmp.estimate_size()
            new_estimated_fee = int(new_estimated_size * fee_rate)

            if new_estimated_fee != estimated_network_fee:
                estimated_network_fee = new_estimated_fee
                continue  # Re-loop if fee changed
            break  # Fee stabilized
   
        inputs_for_send = [(u['txid'], u['output_n']) for u in inputs_with_value]

        # Build final transaction
        tx = wallet.send(
            outputs,
            input_arr=inputs_for_send,
            network=wallet.network.name,
            fee=estimated_network_fee,
            broadcast=broadcast
        )

        result = {
            "txid": tx.txid,
            "raw_hex": tx.as_hex(),
            "inputs_used": inputs_with_value,
            "outputs": outputs,
            "network_fee_sats": estimated_network_fee,
            "service_fee_sats": service_fee_satoshi,
            "change_sats": change_satoshi,
            "tx_size_bytes": new_estimated_size,
            "broadcasted": broadcast,
            "success": True
        }
        
        if broadcast:
            result["explorer_url"] = f"https://blockstream.info/{'testnet/' if self.wallet.network.name == 'testnet' else ''}tx/{tx.txid}"
        
        return result

   
    def send_with_service_fee_deducted(self, to_address, amount_btc, fee_priority="halfHour",
                                   dust_limit=546, broadcast=False):
        """
        Send BTC, deducting all fees (network + service) from the amount.
        Service fee is fixed at 1000 sats.
        """
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        if amount_btc <= 0:
            raise ValueError("Amount must be positive")
        if not self.fee_address:
            raise ValueError("Service fee address not configured")
        if to_address == self.fee_address:
            raise ValueError("Recipient cannot be the service fee address")

        wallet = self.wallet
        amount_satoshi = to_satoshis(amount_btc)
        fee_rate = get_fee_rate(fee_priority)  # sat/vB
        service_fee_satoshi = 1000  # fixed service fee

        if amount_satoshi <= service_fee_satoshi + dust_limit:
            raise ValueError("Amount too small to cover service fee and network fee")

        rough_fee = int(200 * fee_rate)
        total_to_cover = amount_satoshi + service_fee_satoshi + rough_fee
        balance = wallet.balance()
        if total_to_cover > balance:
            raise ValueError("Insufficient funds for transaction including service fee and estimated network fee")

        # Total amount to cover is amount_satoshi (network fee comes from this)
        selected_inputs = wallet.select_inputs(total_to_cover)
        if not selected_inputs:
            raise ValueError("Insufficient UTXOs for transaction")

        # Build inputs with values
        utxos = {u['txid']: u for u in wallet.utxos()}
        inputs_with_value = []
        total_input = 0
        for inp in selected_inputs:
            key = inp.prev_txid.hex()
            if key not in utxos:
                raise ValueError(f"UTXO not found for input {key}")
            u = utxos[key]
            inputs_with_value.append({
                "txid": u['txid'],
                "output_n": u['output_n'],
                "value": u['value'],
                "address": u['address']
            })
            total_input += u['value']

        # Initial outputs (recipient gets amount minus fees)
        outputs = [(to_address, amount_satoshi)]
        outputs.append((self.fee_address, service_fee_satoshi))

        # Estimate network fee
        tx_tmp = Transaction(network=wallet.network.name)
        for u in inputs_with_value:
            tx_tmp.add_input(u["txid"], u["output_n"], value=u["value"], address=u["address"])
        for addr, amt in outputs:
            tx_tmp.add_output(amt, addr)

        estimated_size = tx_tmp.estimate_size()
        estimated_network_fee = int(estimated_size * fee_rate)

        # Deduct network fee from recipient amount
        outputs[0] = (to_address, outputs[0][1] - estimated_network_fee - service_fee_satoshi)
        if outputs[0][1] < dust_limit:
            raise ValueError("Amount too small after deducting fees")

        # Add change if needed
        change_satoshi = total_input - sum([amt for _, amt in outputs])
        if change_satoshi > dust_limit:
            outputs.append((wallet.get_key(change=True).address, change_satoshi))
        else:
            change_satoshi = 0

        # Final input array for wallet.send
        inputs_for_send = [(u['txid'], u['output_n']) for u in inputs_with_value]
        
        tx = wallet.send(
            outputs,
            input_arr=inputs_for_send,
            network=wallet.network.name,
            fee=estimated_network_fee,
            broadcast=broadcast
        )

        result = {
            "txid": tx.txid,
            "raw_hex": tx.as_hex(),
            "inputs_used": inputs_with_value,
            "outputs": outputs,
            "network_fee_sats": estimated_network_fee,
            "service_fee_sats": service_fee_satoshi,
            "change_sats": change_satoshi,
            "tx_size_bytes": estimated_size,
            "broadcasted": broadcast,
            "success": True
        }
        
        if broadcast:
            result["explorer_url"] = f"https://blockstream.info/{'testnet/' if self.wallet.network.name == 'testnet' else ''}tx/{tx.txid}"
        
        return result

    
    def list_transactions(self):
        """List all wallet transactions with accurate sent/received amounts"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")

        txs = self.wallet.transactions()
        wallet_addresses = [k.address for k in self.wallet.keys()]
        transactions = []

        for tx in txs:
            tx_dict = tx.as_dict()

            # Determine if any input is ours (send) or all outputs are ours (receive)
            input_addresses = [inp["address"] for inp in tx_dict.get("inputs", [])]
            output_addresses = [out["address"] for out in tx_dict.get("outputs", [])]

            is_send = any(addr in wallet_addresses for addr in input_addresses)
            direction = "send" if is_send else "receive"

            # Calculate amounts
            total_input_sats = sum(inp["value"] for inp in tx_dict.get("inputs", []) if inp["address"] in wallet_addresses)
            total_output_sats = sum(out["value"] for out in tx_dict.get("outputs", []) if out["address"] in wallet_addresses)

            # Net BTC for this wallet
            value_btc = -to_btc(total_input_sats - total_output_sats) if is_send else to_btc(total_output_sats)

            # Transaction status
            confirmations = tx_dict.get("confirmations", 0)
            status = {"confirmed": confirmations > 0, "confirmations": confirmations}

            transactions.append({
                "txid": tx_dict.get("txid"),
                "direction": direction,
                "value_btc": value_btc,
                "fee_btc": float(to_btc(tx_dict.get("fee", 0))),
                "service_fee": 0.0,
                "input_addresses": input_addresses,
                "output_addresses": output_addresses,
                "status": status,
                "raw_hex": tx_dict.get("raw"),
                "size": tx_dict.get("size", 0),
                "explorer_url": f"https://blockstream.info/{'testnet/' if self.wallet.network == 'testnet' else ''}tx/{tx_dict.get('txid')}",
                "comment": tx_dict.get("comment", "")
            })

        return {"transactions": transactions, "total_count": len(transactions)}


   
    def generate_receive_qrcode(self, amount=None, address=None):
        """Generate QR code for receiving payments"""
        if not address:
            address_info = self.get_new_address()
            address = address_info["address"]
        
        uri = f"bitcoin:{address}"
        if amount is not None:
            uri += f"?amount={amount}"
        
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            "address": address,
            "uri": uri,
            "qr_code": f"data:image/png;base64,{qr_base64}",
            "amount": amount
        }

   
    def get_wallet_info(self):
        """Get comprehensive wallet information"""
        if not self.wallet:
            raise BitcoinRPCError("No wallet loaded")
        
        balance = self.get_balance()
        utxos = self.get_utxos()
        addresses = self.wallet.addresslist()
        
        return {
            "name": self.wallet.name,
            "balance": balance,
            "utxo_count": len(utxos),
            "address_count": len(addresses),
            "network": self.wallet.network.name,
            "transactions_count": len(self.wallet.transactions()),
            "wallet_id": self.wallet.wallet_id
        }

   
    def track_transaction(self, txid):
        """Track a transaction in the network"""
        return self.tracker.get_transaction_status(txid)

    # Static methods don't need error handling decorator
    @staticmethod
    def generate_mnemonic(words=12, language="english"):
        """Generate a BIP39 mnemonic phrase"""
        mnemonic = Mnemonic(language)
        strength = {12: 128, 24: 256}.get(words)
        if not strength:
            raise ValueError("Only 12 or 24 words are supported")
        return {
            "mnemonic": mnemonic.generate(strength=strength),
            "word_count": words,
            "language": language
        }

    @staticmethod
    def get_fee_rate(priority="halfHour"):
        """
        Get recommended Bitcoin fee rate in sat/vbyte using mempool.space API.
        """
        priority_map = {
            "halfHour": "halfHourFee",
            "hour": "hourFee",
            "fastest": "fastestFee",
            "minimum": "minimumFee"
        }
        
        try:
            url = "https://mempool.space/api/v1/fees/recommended"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            fee_rate = data.get(priority_map.get(priority, "halfHourFee"), 10)
            return {
                "fee_rate": fee_rate,
                "priority": priority,
                "source": "mempool.space"
            }
        except Exception as e:
            logger.warning(f"Failed to get fee rate: {e}")
            return {
                "fee_rate": 10,
                "priority": priority,
                "source": "fallback",
                "error": str(e)
            }