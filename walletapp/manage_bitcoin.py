import logging
from decimal import Decimal
from io import BytesIO
import base64
import requests
import qrcode
from bitcoinlib.wallets import Wallet, wallet_create_or_open, WalletError
from bitcoinlib.transactions import Transaction
from bitcoinlib.mnemonic import Mnemonic

# Logger setup
logger = logging.getLogger("wallet")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def to_satoshis(amount):
    return int(Decimal(amount) * Decimal(1e8))

def to_btc(satoshis):
    return Decimal(satoshis) / Decimal(1e8)

def get_btc_usd_price():
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
        logger.warning(f"Failed to get fee rate: {e}")
        return 10

class TransactionTracker:
    def __init__(self, network="testnet"):
        self.network = network
        self.base_url = f"https://blockstream.info/{'testnet/' if network == 'testnet' else ''}api"

    def get_transaction_status(self, txid):
        try:
            url = f"{self.base_url}/tx/{txid}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                tx_data = resp.json()
                confirmations = tx_data.get("status", {}).get("block_height", 0)
                return {"confirmed": confirmations > 0, "confirmations": confirmations}
            else:
                return {"confirmed": False, "confirmations": 0, "error": "Transaction not found"}
        except Exception as e:
            logger.error(f"Error tracking transaction {txid}: {e}")
            return {"confirmed": False, "confirmations": 0, "error": str(e)}

class BitcoinService:
    def __init__(self, wallet_name=None, fee_address=None, network="testnet"):
        self.wallet_name = wallet_name
        self.wallet = wallet_create_or_open(wallet_name, network=network) if wallet_name else None
        self.fee_address = fee_address
        self.network = network
        self.tracker = TransactionTracker(network)

    def create_wallet(self, wallet_name, mnemonic=None):
        self.wallet = wallet_create_or_open(wallet_name, keys=mnemonic, network=self.network)
        logger.info(f"Wallet {wallet_name} loaded or created.")
        return {"wallet_name": wallet_name, "address": self.wallet.get_key().address}

    def restore_wallet(self, wallet_name, keys):
        self.wallet = wallet_create_or_open(wallet_name, keys=keys, network=self.network)
        logger.info(f"Wallet {wallet_name} restored or loaded.")
        return {"wallet_name": wallet_name, "address": self.wallet.get_key().address}

    def backup_wallet(self):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        key = self.wallet.get_key()
        return {"wif": key.wif()}

    def get_balance(self, include_usd=True):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        balance_sat = self.wallet.balance()
        balance_btc = to_btc(balance_sat)
        result = {"satoshis": int(balance_sat), "btc": float(balance_btc)}
        if include_usd:
            usd_price = get_btc_usd_price()
            result["usd_value"] = float(balance_btc * Decimal(usd_price))
            result["btc_price_usd"] = float(usd_price)
        return result

    def get_new_address(self, change=False):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        key = self.wallet.get_key(change=change)
        return {"address": key.address}

    def get_utxos(self):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        utxos = self.wallet.utxos()
        return [{"txid": u['txid'], "output_n": u['output_n'], "value": u['value'],
                 "value_btc": float(to_btc(u['value'])), "address": u['address']} for u in utxos]

    def send_to_address(self, to_address, amount, broadcast=False):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        if amount <= 0:
            raise ValueError("Amount must be positive")
        tx = self.wallet.send_to(to_address, to_satoshis(amount), broadcast=broadcast)
        return {"txid": tx.txid, "amount_btc": float(amount), "to_address": to_address,
                "fee_btc": float(to_btc(tx.fee)), "tx_hex": tx.as_hex(),
                "explorer_url": f"https://blockstream.info/{'testnet/' if self.wallet.network.name == 'testnet' else ''}tx/{tx.txid}",
                "broadcasted": broadcast}

    def send_with_service_fee(self, to_address, amount_btc, service_fee_percent=0.04,
                              fee_priority="halfHour", dust_limit=546, broadcast=False):
        # Implementation as previously provided
        pass  # Include the earlier full method

    def send_with_service_fee_deducted(self, to_address, amount_btc, fee_priority="halfHour",
                                       dust_limit=546, broadcast=False):
        # Implementation as previously provided
        pass  # Include the earlier full method

    def list_transactions(self):
        if not self.wallet:
            raise RuntimeError("No wallet loaded")
        txs = self.wallet.transactions()
        wallet_addresses = [k.address for k in self.wallet.keys()]
        transactions = []
        for tx in txs:
            tx_dict = tx.as_dict()
            input_addresses = [inp["address"] for inp in tx_dict.get("inputs", [])]
            output_addresses = [out["address"] for out in tx_dict.get("outputs", [])]
            is_send = any(addr in wallet_addresses for addr in input_addresses)
            direction = "send" if is_send else "receive"
            total_input_sats = sum(inp["value"] for inp in tx_dict.get("inputs", []) if inp["address"] in wallet_addresses)
            total_output_sats = sum(out["value"] for out in tx_dict.get("outputs", []) if out["address"] in wallet_addresses)
            value_btc = -to_btc(total_input_sats - total_output_sats) if is_send else to_btc(total_output_sats)
            confirmations = tx_dict.get("confirmations", 0)
            transactions.append({"txid": tx_dict.get("txid"), "direction": direction, "value_btc": value_btc,
                                 "fee_btc": float(to_btc(tx_dict.get("fee", 0))), "input_addresses": input_addresses,
                                 "output_addresses": output_addresses, "status": {"confirmed": confirmations > 0, "confirmations": confirmations},
                                 "raw_hex": tx_dict.get("raw"),
                                 "explorer_url": f"https://blockstream.info/{'testnet/' if self.wallet.network.name == 'testnet' else ''}tx/{tx_dict.get('txid')}"})
        return {"transactions": transactions, "total_count": len(transactions)}

    def generate_receive_qrcode(self, amount=None, address=None):
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
        return {"address": address, "uri": uri, "qr_code": f"data:image/png;base64,{qr_base64}", "amount": amount}

    def track_transaction(self, txid):
        return self.tracker.get_transaction_status(txid)

    @staticmethod
    def generate_mnemonic(words=12, language="english"):
        mnemonic = Mnemonic(language)
        strength = {12: 128, 24: 256}.get(words)
        if not strength:
            raise ValueError("Only 12 or 24 words supported")
        return {"mnemonic": mnemonic.generate(strength=strength), "word_count": words, "language": language}
