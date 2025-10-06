import threading
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Invoice
from .blink_ws import start_blink_ws  # your websocket function

# Global flag to ensure WS is not started multiple times
ws_thread = None
ws_thread_lock = threading.Lock()


def run_blink_ws_thread():
    """Run Blink WS in a daemon thread."""
    global ws_thread
    if ws_thread and ws_thread.is_alive():
        return  # Already running

    ws_thread = threading.Thread(target=start_blink_ws, daemon=True)
    ws_thread.start()


@receiver(post_save, sender=Invoice)
def start_ws_on_invoice(sender, instance, created, **kwargs):
    """
    Start Blink WS thread if:
    - A new invoice is created
    - Or there are any pending invoices
    """
    if created or Invoice.objects.filter(status="pending").exists():
        with ws_thread_lock:
            run_blink_ws_thread()
