import requests
import os
import bolt11
import time

class BlinkWallet:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("BLINK_API_KEY")
        if not self.api_key:
            raise ValueError("API key not provided and BLINK_API_KEY not set in environment.")
        self.api_url = "https://api.blink.sv/graphql"

    def _post_query(self, query, variables=None):
        """
        Internal helper to send GraphQL queries with optional variables.
        """
        headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        response = requests.post(self.api_url, json=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Query failed with status {response.status_code}: {response.text}")
        return response.json()

    def get_wallets(self):
        query = """
        query Me {
          me {
            defaultAccount {
              wallets {
                id
                walletCurrency
                balance
              }
            }
          }
        }
        """
        data = self._post_query(query)
        wallets = data.get("data", {}).get("me", {}).get("defaultAccount", {}).get("wallets", [])
        return wallets

    def get_btc_wallet(self):
        wallets = self.get_wallets()
        for w in wallets:
            if w["walletCurrency"] == "BTC":
                return w
        return None

    def get_usd_wallet(self):
        wallets = self.get_wallets()
        for w in wallets:
            if w["walletCurrency"] == "USD":
                return w
        return None
    def create_ln_invoice(self, amount, wallet_id=None):
        """
        Create a Lightning invoice for BTC.

        Args:
            amount (int): Amount in satoshis to receive.
            wallet_id (str): BTC wallet ID. If None, uses default BTC wallet.

        Returns:
            dict: Invoice details including paymentRequest, paymentHash, paymentSecret, satoshis.
        """
        # Get BTC wallet ID if not provided
        if wallet_id is None:
            btc_wallet = self.get_btc_wallet()
            if not btc_wallet:
                raise ValueError("No BTC wallet found.")
            wallet_id = btc_wallet["id"]

        query = """
        mutation LnInvoiceCreate($input: LnInvoiceCreateInput!) {
        lnInvoiceCreate(input: $input) {
            invoice {
            paymentRequest
            paymentHash
            paymentSecret
            satoshis
            }
            errors {
            message
            }
        }
        }
        """

        variables = {
            "input": {
                "walletId": wallet_id,
                "amount": int(amount)  # <-- changed from "satoshis" to "amount"
            }
        }

        result = self._post_query(query, variables)

        ln_invoice = result.get("data", {}).get("lnInvoiceCreate", {})
        errors = ln_invoice.get("errors", [])
        if errors:
            raise Exception(f"Error creating invoice: {errors[0]['message']}")

        invoice = ln_invoice.get("invoice")
        return invoice

    # def pay_ln_invoice(self, payment_request, wallet_id=None):
    #     """
    #     Pay a Lightning invoice (BOLT11) from your BTC wallet.
    #     """
    #     if wallet_id is None:
    #         btc_wallet = self.get_btc_wallet()
    #         if not btc_wallet:
    #             raise ValueError("No BTC wallet found.")
    #         wallet_id = btc_wallet["id"]

    #     query = """
    #     mutation LnInvoicePaymentSend($input: LnInvoicePaymentInput!) {
    #       lnInvoicePaymentSend(input: $input) {
    #         status
    #         errors {
    #           message
    #           path
    #           code
    #         }
    #       }
    #     }
    #     """

    #     variables = {
    #         "input": {
    #             "walletId": str(wallet_id),
    #             "paymentRequest": payment_request
    #         }
    #     }

    #     result = self._post_query(query, variables)
    #     payment = result.get("data", {}).get("lnInvoicePaymentSend", {})
    #     return payment
    def pay_ln_invoice(self, payment_request, amount=None):
        """
        Pay a Lightning invoice.
        - Normal invoice: pays embedded amount automatically.
        - Zero-amount invoice: requires 'amount' in sats.
        """
        try:
            invoice = bolt11.decode(payment_request)
        except Exception as e:
            return {"error": f"Invalid invoice: {e}"}

        invoice_amount_msat = getattr(invoice, "amount_msat", None)

        if invoice_amount_msat and invoice_amount_msat > 0:
            # Invoice already has an amount
            final_amount = invoice_amount_msat // 1000
            msg_amount = f"Invoice amount: {final_amount} sats"
        elif amount:
            # Zero-amount invoice, use provided amount
            final_amount = int(amount)
            msg_amount = f"Zero-amount invoice, using provided {final_amount} sats"
        else:
            return {"error": "Zero-amount invoice detected. You must provide an amount."}

        # Check invoice expiry
        created = getattr(invoice, "date", 0)
        expiry = getattr(invoice, "expiry", 0)
        now = int(time.time())
        if expiry and now > created + expiry:
            return {"error": "Invoice expired."}

        wallet_id = self.get_btc_wallet()["id"]

        # Use LnInvoicePaymentSend for normal invoices
        # For zero-amount invoices, Blink may support 'amountSat' field
        query = """
        mutation LnInvoicePaymentSend($input: LnInvoicePaymentInput!) {
            lnInvoicePaymentSend(input: $input) {
                status
                errors {
                    message
                    path
                    code
                }
            }
        }
        """

        input_data = {
            "walletId": str(wallet_id),
            "paymentRequest": payment_request
        }

        # # Only include amountSat if invoice is zero-amount
        # if invoice_amount_msat is None:
        #     input_data["amount"] = final_amount

        variables = {"input": input_data}
        result = self._post_query(query, variables)

        return {
            "check": msg_amount,
            "payment": result,
            "amount": final_amount
        }




    def pay_ln_address(self, ln_address, amount, wallet_id=None):
        """
        Send BTC to a Lightning Address.
        """
        if wallet_id is None:
            btc_wallet = self.get_btc_wallet()
            if not btc_wallet:
                raise ValueError("No BTC wallet found.")
            wallet_id = btc_wallet["id"]

        query = """
        mutation LnAddressPaymentSend($input: LnAddressPaymentSendInput!) {
          lnAddressPaymentSend(input: $input) {
            status
            errors {
              code
              message
              path
            }
          }
        }
        """

        variables = {
            "input": {
                "walletId": str(wallet_id),
                "amount": int(amount),
                "lnAddress": ln_address
            }
        }

        result = self._post_query(query, variables)
        payment = result.get("data", {}).get("lnAddressPaymentSend", {})
        return payment

    def pay_lnurl(self, lnurl, amount, wallet_id=None):
        """
        Send BTC to a static LNURL payRequest.
        """
        if wallet_id is None:
            btc_wallet = self.get_btc_wallet()
            if not btc_wallet:
                raise ValueError("No BTC wallet found.")
            wallet_id = btc_wallet["id"]

        query = """
        mutation LnurlPaymentSend($input: LnurlPaymentSendInput!) {
          lnurlPaymentSend(input: $input) {
            status
            errors {
              code
              message
              path
            }
          }
        }
        """

        variables = {
            "input": {
                "walletId": str(wallet_id),
                "amount": int(amount),
                "lnurl": lnurl
            }
        }

        result = self._post_query(query, variables)
        payment = result.get("data", {}).get("lnurlPaymentSend", {})
        return payment
   
    def probe_ln_invoice_fee(self, payment_request, wallet_id=None):
        """
        Estimate the fee for paying a Lightning invoice.

        Args:
            payment_request (str): BOLT11 invoice string.
            wallet_id (str, optional): BTC wallet ID. Uses default BTC wallet if None.

        Returns:
            dict: Contains 'amount' (fee in satoshis) and any 'errors'.
        """
        if wallet_id is None:
            btc_wallet = self.get_btc_wallet()
            if not btc_wallet:
                raise ValueError("No BTC wallet found.")
            wallet_id = btc_wallet["id"]

        query = """
        mutation lnInvoiceFeeProbe($input: LnInvoiceFeeProbeInput!) {
          lnInvoiceFeeProbe(input: $input) {
            errors {
              message
            }
            amount
          }
        }
        """

        variables = {
            "input": {
                "walletId": str(wallet_id),
                "paymentRequest": payment_request
            }
        }

        result = self._post_query(query, variables)
        probe = result.get("data", {}).get("lnInvoiceFeeProbe", {})
        return probe
    def generate_qr(self, data):
        import qrcode
        import io
        import base64

        # Generate QR code
        qr = qrcode.QRCode()
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Save image to memory
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Encode as Base64 string
        encoded = base64.b64encode(buffer.read()).decode("utf-8")
        return f"data:image/png;base64,{encoded}"


