# blink_ws_scheduler.py
import threading
from .blink_ws import start_blink_ws

WS_THREAD = None
WS_INTERVAL = 60  # seconds, check/start WS every 60s

def schedule_blink_ws():
    global WS_THREAD

    # Only start a new thread if none is running or it’s not alive
    if WS_THREAD is None or not WS_THREAD.is_alive():
        print("[Scheduler] 📡 Starting Blink WS thread...")
        WS_THREAD = threading.Thread(target=start_blink_ws, daemon=True)
        WS_THREAD.start()
    else:
        print("[Scheduler] 🔁 Blink WS thread already running")

    # Reschedule itself
    threading.Timer(WS_INTERVAL, schedule_blink_ws).start()
