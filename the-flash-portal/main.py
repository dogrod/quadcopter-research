import sys
import signal
import asyncio

from . import app, socketio
from .wifi_monitor import WifiMonitor
from .mavlink_monitor import MAVLinkMonitor

wifi_monitor = WifiMonitor()
mavlink_monitor = MAVLinkMonitor()

def stop_event_loop(loop):
    try:
        if not loop.is_closed():
            print("Stopping event loop...")
            pending_tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending_tasks:
                task.cancel()
                try:
                    loop.run_until_complete(task)
                except asyncio.CancelledError:
                    print(f"Cancelled task: {task}")

            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            print("Event loop closed.")
    except RuntimeError as e:
        print(f"Error closing event loop: {e}")


def signal_handler(sig, frame):
    print("Gracefully shutting down...")
    
    # Stop monitoring
    if wifi_monitor.monitoring:
        wifi_monitor.stop_capture_event.set()
    
    if mavlink_monitor.thread and mavlink_monitor.thread.is_alive():
        mavlink_monitor.stop_event.set()
        mavlink_monitor.thread.join()

    # Stop the event loop
    loop = asyncio.get_event_loop()
    stop_event_loop(loop)
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        socketio.run(app, host="0.0.0.0", port=5001)
    except KeyboardInterrupt:
        print("Server interrupted by user. Shutting down...")
        loop = asyncio.get_event_loop()
        stop_event_loop(loop)
        sys.exit(0)

if __name__ == "__main__":
    main()