import json
import time
import websocket
from django.utils import timezone
from .models import Invoice
from .utils import handle_paid_invoice

BLINK_WS_URL = "wss://ws.blink.sv/graphql"
API_KEY = "blink_bPc4Pm67gHpIElVjxgAgSEMuSmOntM0o8tPWOMSzeme8wpMvG8mT1GSb03UziTTy"
BATCH_SIZE = 5  # Process 5 invoices at a time

def start_blink_ws():
    """Track unpaid invoices and credit wallets on payment."""

    def on_open(ws):
        print("[Blink WS] ✅ Connected")

        # Init connection
        ws.send(json.dumps({"type": "connection_init", "payload": {}}))

        # Subscribe to myUpdates (general LN events)
        query_myupdates = """
        subscription {
            myUpdates {
                update {
                    ... on LnUpdate {
                        transaction {
                            initiationVia {
                                ... on InitiationViaLn {
                                    paymentHash
                                }
                            }
                            direction
                            status
                            settlementAmount
                        }
                    }
                }
            }
        }
        """
        ws.send(json.dumps({
            "id": "invoice_monitor",
            "type": "subscribe",
            "payload": {"query": query_myupdates}
        }))
        print("[Blink WS] 🔔 Subscribed to myUpdates")

        # Subscribe to first batch of unpaid invoices
        subscribe_invoice_batch(ws)

    def subscribe_invoice_batch(ws):
        unpaid_invoices = Invoice.objects.filter(status="pending")[:BATCH_SIZE]
        print(f"[Blink WS] 🧾 Subscribing to {unpaid_invoices.count()} unpaid invoices...")
        for invoice in unpaid_invoices:
            ws.send(json.dumps({
                "id": f"ln_invoice_{invoice.id}",
                "type": "subscribe",
                "payload": {
                    "query": """
                    subscription LnInvoicePaymentStatus($input: LnInvoicePaymentStatusInput!) {
                        lnInvoicePaymentStatus(input: $input) {
                            status
                            errors { code message path }
                        }
                    }
                    """,
                    "variables": {"input": {"paymentRequest": invoice.payment_request}}
                }
            }))

    def on_message(ws, message):
        try:
            data = json.loads(message)
            payload = data.get("payload", {})

            # Handle connection acknowledgment
            if data.get("type") == "connection_ack":
                print("[Blink WS] 🔗 Connection acknowledged")
                return

            # Only process "next" messages
            if data.get("type") != "next":
                return

            # Handle myUpdates (incoming payments)
            if "myUpdates" in str(payload):
                updates_data = payload.get("data", {}).get("myUpdates", {})
                update = updates_data.get("update", {})
                tx = update.get("transaction", {})
                direction = tx.get("direction")
                status = tx.get("status")
                initiation_via = tx.get("initiationVia", {})
                payment_hash = initiation_via.get("paymentHash")
                settlement_amount = tx.get("settlementAmount", 0)

                if direction == "RECEIVE" and status == "SUCCESS" and payment_hash:
                    handle_paid_invoice(payment_hash, settlement_amount)

            # Handle lnInvoicePaymentStatus events
            elif "lnInvoicePaymentStatus" in str(payload):
                status_data = payload.get("data", {}).get("lnInvoicePaymentStatus", {})
                status_value = status_data.get("status")
                message_id = data.get("id", "")
                if message_id.startswith("ln_invoice_"):
                    invoice_id = message_id.replace("ln_invoice_", "")
                    try:
                        invoice = Invoice.objects.get(id=invoice_id)
                        if status_value == "PAID" and invoice.status != "paid":
                            handle_paid_invoice(invoice.payment_request, invoice.amount or 0)
                        elif status_value == "EXPIRED":
                            invoice.status = "expired"
                            invoice.save()
                    except Invoice.DoesNotExist:
                        print(f"[Blink WS] ⚠️ Invoice {invoice_id} not found")

        except Exception as e:
            print(f"[Blink WS] ⚠️ Error handling message: {e}")
            import traceback
            traceback.print_exc()

        # Check if batch complete, subscribe next batch
        subscribe_invoice_batch(ws)

    def on_error(ws, error):
        print(f"[Blink WS] ❌ WebSocket Error: {error}")

    def on_close(ws, close_status_code, close_msg):
        print(f"[Blink WS] 🔌 Closed: {close_status_code} - {close_msg}")
        time.sleep(5)
        start_blink_ws()

    ws = websocket.WebSocketApp(
        BLINK_WS_URL,
        subprotocols=["graphql-transport-ws"],
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header={
            f"X-API-KEY": API_KEY,
            "User-Agent": "BlinkWSClient/1.0"
        }
    )

    ws.run_forever()
