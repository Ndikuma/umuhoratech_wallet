import time
from threading import Thread
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Invoice
from .utils import process_pending_invoices  # your existing function


def run_in_background(func, *args, **kwargs):
    """Run a function asynchronously in a separate thread."""
    Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()


def delayed_process_pending():
    """Wait 5 seconds, then process all pending invoices."""
    time.sleep(5)
    print("Checking for pending invoices after 5s...")
    process_pending_invoices()


@receiver(post_save, sender=Invoice)
def invoice_post_save(sender, instance, created, **kwargs):
    """
    Trigger background processing of all pending invoices
    after 5 seconds, so invoice creation is not blocked.
    """
    if instance.status == "pending":
        run_in_background(delayed_process_pending)
