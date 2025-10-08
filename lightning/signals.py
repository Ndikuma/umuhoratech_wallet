from threading import Thread
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Invoice
from .utils import process_pending_invoices  # your existing function

def run_in_background(func, *args, **kwargs):
    Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()

@receiver(post_save, sender=Invoice)
def invoice_post_save(sender, instance, created, **kwargs):
    """
    Trigger processing of pending invoices in the background,
    so invoice creation is not blocked.
    """
    if instance.status == "pending":
        run_in_background(process_pending_invoices)
