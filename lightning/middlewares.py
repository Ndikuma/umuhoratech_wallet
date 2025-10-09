import threading
import time
from datetime import datetime, timedelta
from django.utils.deprecation import MiddlewareMixin
from .models import Invoice
from .utils import process_pending_invoices

# Global state control
_lock = threading.Lock()
_is_running = False
_last_run = None  # Timestamp of last background execution
_COOLDOWN_SECONDS = 120  # 2 minutes


def run_in_background():
    """Run invoice scanning in background (non-blocking, with cooldown)."""
    global _is_running, _last_run

    # ✅ Skip if no pending invoices
    if not Invoice.objects.filter(status="pending").exists():
        return

    now = datetime.now()

    # ✅ Skip if cooldown not passed yet
    if _last_run and (now - _last_run) < timedelta(seconds=_COOLDOWN_SECONDS):
        return

    with _lock:
        if _is_running:
            # Another thread is already running
            return
        _is_running = True
        _last_run = now  # mark start time

    def background_task():
        global _is_running
        try:
            print(f"[Middleware] Background scan starting at {datetime.now().strftime('%H:%M:%S')}...")
            time.sleep(3)  # slight delay before checking
            process_pending_invoices()
        except Exception as e:
            print(f"[Middleware] Error during invoice scan: {e}")
        finally:
            _is_running = False
            print(f"[Middleware] Background scan finished at {datetime.now().strftime('%H:%M:%S')}.")

    thread = threading.Thread(target=background_task, daemon=True)
    thread.start()


class BackgroundInvoiceMiddleware(MiddlewareMixin):
    """
    Middleware that triggers non-blocking background checks for pending invoices.
    Runs at most once every 2 minutes, only when invoices exist.
    """

    def process_request(self, request):
        run_in_background()
        return None
