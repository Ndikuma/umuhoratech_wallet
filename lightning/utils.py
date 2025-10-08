from django.db import transaction
from django.utils import timezone
# payments/utils.py
import requests
from .models import Invoice, WalletLocal
from django.utils import timezone

BLINK_API_URL = "https://api.blink.sv/graphql"
BLINK_API_KEY = "blink_bPc4Pm67gHpIElVjxgAgSEMuSmOntM0o8tPWOMSzeme8wpMvG8mT1GSb03UziTTy"


@transaction.atomic
def handle_paid_invoice(payment_request: str, amount: int):
    """
    Handle an external paid invoice:
    - Mark as paid
    - Credit user's wallet
    """
    try:
        invoice = Invoice.objects.select_for_update().get(payment_request=payment_request)
    except Invoice.DoesNotExist:
        print(f"[Invoice Handler] ⚠️ External invoice not found: {payment_request}")
        return

    if invoice.status == "paid":
        print(f"[Invoice Handler] ⚠️ Invoice already marked as paid: {payment_request}")
        return

    # Mark invoice as paid
    invoice.status = "paid"
    invoice.paid_at = timezone.now()
    invoice.save()
    print(f"[Invoice Handler] ✅ External invoice {invoice.id} marked as paid")

    # Credit user's wallet
    wallet = invoice.wallet
    wallet.add_balance(amount)
    print(f"[Invoice Handler] 💰 Credited {amount} sats to {wallet.user.username}")


def get_received_transactions(first=50):
    """
    Fetch received transactions from Blink API
    """
    query = """
    query Transactions($first: Int) {
      me {
        defaultAccount {
          transactions(first: $first) {
            edges {
              node {
                id
                createdAt
                settlementAmount
                status
                direction
                initiationVia { ... on InitiationViaLn { paymentHash } }
              }
            }
          }
        }
      }
    }
    """
    variables = {"first": first}
    headers = {
        "X-API-KEY": BLINK_API_KEY,
        "Content-Type": "application/json"
    }

    response = requests.post(BLINK_API_URL, json={"query": query, "variables": variables}, headers=headers)
    if response.status_code != 200:
        print("Error fetching transactions:", response.text)
        return []

    edges = response.json().get("data", {}).get("me", {}).get("defaultAccount", {}).get("transactions", {}).get("edges", [])
    print(edges)
    transactions = [
        {
            "id": edge["node"]["id"],
            "payment_hash": edge["node"]["initiationVia"].get("paymentHash"),
            "amount": edge["node"]["settlementAmount"],
            "status": edge["node"]["status"]
        }
        for edge in edges if edge["node"]["direction"] == "RECEIVE"
    ]
    return transactions


def handle_received_transaction(payment_hash, amount):
    """
    Mark invoice paid and credit wallet
    """
    try:
        invoice = Invoice.objects.get(payment_hash=payment_hash, status="pending")
    except Invoice.DoesNotExist:
        print(f"[Blink] No pending invoice found for payment_hash {payment_hash}")
        return False

    invoice.mark_paid()

    wallet = invoice.wallet
    wallet.add_balance(amount)
    print(f"[Invoice Handler] 💰 Credited {amount} sats to {wallet.user.username}")
    return True

# payments/utils.py
from django.db import transaction
from django.utils import timezone
from .models import Invoice
import requests

BLINK_API_URL = "https://api.blink.sv/graphql"
BLINK_API_KEY = "blink_bPc4Pm67gHpIElVjxgAgSEMuSmOntM0o8tPWOMSzeme8wpMvG8mT1GSb03UziTTy"


@transaction.atomic
def scan_and_credit_all_pending_invoices(initial_batch=50, batch_increment=50):
    """
    Scan all pending invoices in DB and credit wallets if matched with received transactions.
    Dynamically increases batch size until all pending invoices are checked.
    """
    pending_invoices = Invoice.objects.filter(status="pending")
    if not pending_invoices.exists():
        print("[Scan] No pending invoices found.")
        return

    batch_size = initial_batch
    while pending_invoices.exists():
        print(f"[Scan] Fetching last {batch_size} transactions from Blink...")
        
        # Fetch transactions from Blink API
        query = """
        query Transactions($first: Int) {
          me {
            defaultAccount {
              transactions(first: $first) {
                edges {
                  node {
                    id
                    createdAt
                    settlementAmount
                    status
                    direction
                    initiationVia { ... on InitiationViaLn { paymentHash } }
                  }
                }
              }
            }
          }
        }
        """
        variables = {"first": batch_size}
        headers = {"X-API-KEY": BLINK_API_KEY, "Content-Type": "application/json"}
        response = requests.post(BLINK_API_URL, json={"query": query, "variables": variables}, headers=headers)

        if response.status_code != 200:
            print("[Scan] Error fetching transactions:", response.text)
            return

        edges = response.json().get("data", {}).get("me", {}).get("defaultAccount", {}).get("transactions", {}).get("edges", [])
        transactions = [
            {
                "id": edge["node"]["id"],
                "payment_hash": edge["node"]["initiationVia"].get("paymentHash"),
                "amount": edge["node"]["settlementAmount"],
                "status": edge["node"]["status"]
            }
            for edge in edges if edge["node"]["direction"] == "RECEIVE"
        ]

        # Track if any invoice was paid in this batch
        any_paid = False

        # Match transactions with pending invoices
        for invoice in pending_invoices:
            for tx in transactions:
                if tx.get("payment_hash") == invoice.payment_hash and tx.get("status") == "SUCCESS":
                    invoice.mark_paid()
                    wallet = invoice.wallet
                    wallet.add_balance(tx.get("amount") or 0)
                    print(f"[Scan] Invoice {invoice.id} paid. Credited {tx.get('amount')} sats to {wallet.user.username}")
                    any_paid = True
                    break  # Stop after matching this invoice

        # Update pending invoices for next iteration
        pending_invoices = Invoice.objects.filter(status="pending")

        if not any_paid and pending_invoices.exists():
            # Increase batch size to fetch more transactions next round
            batch_size += batch_increment
            print(f"[Scan] No new payments found. Increasing batch size to {batch_size}...")

    print("[Scan] All pending invoices processed.")



from django.db import transaction
from django.utils import timezone
from .models import Invoice
import requests

BLINK_API_URL = "https://api.blink.sv/graphql"
BLINK_API_KEY = "blink_bPc4Pm67gHpIElVjxgAgSEMuSmOntM0o8tPWOMSzeme8wpMvG8mT1GSb03UziTTy"


def fetch_received_transactions(batch_size=50):
    """Fetch the latest received transactions from Blink API."""
    query = """
    query Transactions($first: Int) {
      me {
        defaultAccount {
          transactions(first: $first) {
            edges {
              node {
                id
                createdAt
                settlementAmount
                status
                direction
                initiationVia { ... on InitiationViaLn { paymentHash } }
              }
            }
          }
        }
      }
    }
    """
    variables = {"first": batch_size}
    headers = {"X-API-KEY": BLINK_API_KEY, "Content-Type": "application/json"}
    
    response = requests.post(BLINK_API_URL, json={"query": query, "variables": variables}, headers=headers)
    if response.status_code != 200:
        print("[Blink] Error fetching transactions:", response.text)
        return []

    edges = response.json().get("data", {}).get("me", {}).get("defaultAccount", {}).get("transactions", {}).get("edges", [])
    transactions = [
        {
            "id": edge["node"]["id"],
            "payment_hash": edge["node"]["initiationVia"].get("paymentHash"),
            "amount": edge["node"]["settlementAmount"],
            "status": edge["node"]["status"]
        }
        for edge in edges if edge["node"]["direction"] == "RECEIVE"
    ]
    return transactions


@transaction.atomic
def process_pending_invoices(initial_batch=50, batch_increment=50):
    """
    Scan all pending invoices and credit wallets if matched with received transactions.
    Dynamically increases batch size until all pending invoices are scanned.
    """
    pending_invoices = Invoice.objects.filter(status="pending")
    if not pending_invoices.exists():
        return

    batch_size = initial_batch
    while pending_invoices.exists():
        transactions = fetch_received_transactions(batch_size=batch_size)
        if not transactions:
            print("[Scan] No transactions returned from Blink.")
            return

        any_paid = False
        for invoice in pending_invoices:
            for tx in transactions:
                if tx.get("payment_hash") == invoice.payment_hash and tx.get("status") == "SUCCESS":
                    invoice.mark_paid()
                    wallet = invoice.wallet
                    wallet.add_balance(tx.get("amount") or 0)
                    print(f"[Scan] Invoice {invoice.id} paid. Credited {tx.get('amount')} sats to {wallet.user.username}")
                    any_paid = True
                    break

        pending_invoices = Invoice.objects.filter(status="pending")

        if not any_paid and pending_invoices.exists():
            batch_size += batch_increment
            print(f"[Scan] No new payments found. Increasing batch size to {batch_size}...")
    
    print("[Scan] All pending invoices processed.")
