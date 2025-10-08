from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Invoice
from .utils import process_pending_invoices

@receiver(post_save, sender=Invoice)
def invoice_post_save(sender, instance, created, **kwargs):
    """
    Automatically scan and process pending invoices whenever an invoice is saved.
    """
    # Only trigger if invoice is pending
    if instance.status == "pending":
        process_pending_invoices()
