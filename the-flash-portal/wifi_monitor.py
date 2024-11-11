import pyshark

from datetime import datetime
from threading import Event

from . import socketio
from .config import Config

class WifiMonitor:
    def __init__(self, interface):
        self.monitoring = False
        self.stop_capture_event = Event()

    async def close_capture(self, capture):
        try:
            await capture.close_async()
            print("Wi-Fi capture closed successfully.")
        except Exception as e:
            print(f"Error while closing Wi-Fi capture: {e}")

    def start_capture(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = f'/data/wifi/ap_traffic_{timestamp}.pcap'

        try:
            capture = pyshark.LiveCapture(
                interface=Config.WIFI_INTERFACE,
                output_file=pcap_filename
            )

            for packet in capture.sniff_continuously():
                if self.stop_capture_event.is_set():
                    break
                try:
                    data = {
                        "source_ip": packet.ip.src,
                        "destination_ip": packet.ip.dst,
                        "protocol": packet.transport_layer,
                        # "info": str(packet),
                        "length": packet.length,
                    }
                    # print(f"Emitting wifi_packet event: {data}")
                    socketio.emit("wifi_packet", data, namespace="/wifi")
                    socketio.sleep(0.1)
                except AttributeError:
                    # Some packets may not have IP layer
                    continue
        except Exception as e:
            print(f"Error while capturing Wi-Fi traffic: {e}")
            socketio.emit("error", {"message": str(e)}, namespace="/wifi")
        finally:
            print(f"Wi-Fi capture stopped and saved to {pcap_filename}")
            socketio.emit("capture_saved", {"filename": pcap_filename}, namespace="/wifi")

