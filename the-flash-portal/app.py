import asyncio
import signal
import sys
import csv
import pyshark

from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from threading import Thread, Event, Lock
from pathlib import Path

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from pymavlink import mavutil

# Configuration
@dataclass
class Config:
    WIFI_INTERFACE: str = "wlan0"
    MAVLINK_BAUD_RATE: int = 921600
    MAVLINK_STREAM_RATE: int = 10
    DATA_DIR: Path = Path("/data")
    
    def __post_init__(self):
        # Ensure data directories exist
        (self.DATA_DIR / "wifi").mkdir(parents=True, exist_ok=True)
        (self.DATA_DIR / "mavlink").mkdir(parents=True, exist_ok=True)

class MonitoringState:
    def __init__(self):
        self.wifi_monitoring = False
        self.stop_capture_event = Event()
        self.mavlink_connection: Optional[mavutil.mavlink_connection] = None
        self.mavlink_thread: Optional[Thread] = None
        self.mavlink_stop_event = Event()
        self.mavlink_messages: List[Dict] = []
        self.mavlink_message_lock = Lock()

class MonitoringApp:
    def __init__(self):
        self.config = Config()
        self.state = MonitoringState()
        self.app = Flask(__name__)
        self.socketio = SocketIO(
            self.app,
            async_mode="threading",
            cors_allowed_origins="*",
            logger=True,
            engineio_logger=True
        )
        self._setup_routes()
        self._setup_socketio()
        self._setup_signal_handlers()

    def _index(self):
        return render_template("index.html")

    def _dashboard(self):
        return render_template("dashboard.html")

    def _wifi_page(self):
        return render_template("wifi.html")

    def _mavlink_page(self):
        return render_template("mavlink.html")

    def _setup_routes(self):
        # Basic routes with named functions
        self.app.add_url_rule("/", "index", self._index)
        self.app.add_url_rule("/dashboard", "dashboard", self._dashboard)
        self.app.add_url_rule("/wifi", "wifi", self._wifi_page)
        self.app.add_url_rule("/mavlink", "mavlink", self._mavlink_page)
        
        # Control routes
        self.app.add_url_rule(
            "/toggle_wifi_monitoring",
            "toggle_wifi_monitoring",
            self._toggle_wifi_monitor,
            methods=["POST"]
        )
        self.app.add_url_rule(
            "/toggle_mavlink_monitor",
            "toggle_mavlink_monitor",
            self._toggle_mavlink_monitor,
            methods=["POST"]
        )
        self.app.add_url_rule(
            "/toggle_monitoring",
            "toggle_monitoring",
            self._toggle_monitoring,
            methods=["POST"]
        )

    def _setup_socketio(self):
        @self.socketio.on("connect", namespace="/wifi")
        def wifi_connect():
            print("WiFi client connected")
            emit("wifi_status", {"monitoring": self.state.wifi_monitoring})

        @self.socketio.on("connect", namespace="/mavlink")
        def mavlink_connect():
            print("MAVLink client connected")
            status = 'Connected' if (self.state.mavlink_thread and 
                                   self.state.mavlink_thread.is_alive()) else 'Disconnected'
            emit('mavlink_status', {'status': status})

    async def _process_wifi_packet(self, packet):
        try:
            data = {
                "source_ip": packet.ip.src,
                "destination_ip": packet.ip.dst,
                "protocol": packet.transport_layer,
                "length": packet.length,
            }
            self.socketio.emit("wifi_packet", data, namespace="/wifi")
        except AttributeError:
            pass  # Skip packets without IP layer

    async def start_wifi_capture(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_file = self.config.DATA_DIR / "wifi" / f'ap_traffic_{timestamp}.pcap'
        
        try:
            capture = pyshark.LiveCapture(
                interface=self.config.WIFI_INTERFACE,
                output_file=str(pcap_file)
            )
            
            for packet in capture.sniff_continuously():
                if self.state.stop_capture_event.is_set():
                    break
                await self._process_wifi_packet(packet)
                await asyncio.sleep(0.1)
                
        except Exception as e:
            print(f"Error during packet capture: {e}")
            self.socketio.emit('error', {'message': str(e)}, namespace='/wifi')
        finally:
            await capture.close_async()
            print(f"WiFi capture stopped and saved to {pcap_file}")
            self.socketio.emit('capture_saved', {'filename': str(pcap_file)}, namespace='/wifi')

    def configure_mavlink_streams(self, master):
        """Configure MAVLink stream rates"""
        stream_types = [
            mavutil.mavlink.MAV_DATA_STREAM_EXTENDED_STATUS,
            mavutil.mavlink.MAV_DATA_STREAM_POSITION,
            mavutil.mavlink.MAV_DATA_STREAM_EXTRA1,
            mavutil.mavlink.MAV_DATA_STREAM_EXTRA3,
            mavutil.mavlink.MAV_DATA_STREAM_RAW_SENSORS
        ]
        
        for stream_type in stream_types:
            master.mav.request_data_stream_send(
                master.target_system,
                master.target_component,
                stream_type,
                self.config.MAVLINK_STREAM_RATE,
                1
            )

    def save_mavlink_messages(self) -> Optional[str]:
        with self.state.mavlink_message_lock:
            if not self.state.mavlink_messages:
                return None

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.config.DATA_DIR / "mavlink" / f"mavlink_data_{timestamp}.csv"

            try:
                fieldnames = sorted(set().union(*(msg.keys() for msg in self.state.mavlink_messages)))
                with open(filename, mode='w', newline='', buffering=8192) as file:
                    writer = csv.DictWriter(file, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.state.mavlink_messages)
                return str(filename)
            except Exception as e:
                print(f"Error saving MAVLink messages: {e}")
                raise

    def mavlink_listener(self, connection_string: str):
        try:
            self.state.mavlink_connection = mavutil.mavlink_connection(
                connection_string,
                baud=self.config.MAVLINK_BAUD_RATE
            )
            self.configure_mavlink_streams(self.state.mavlink_connection)
            
            self.state.mavlink_connection.wait_heartbeat()
            self.socketio.emit('mavlink_status', {'status': 'Connected'}, namespace='/mavlink')
            
            message_count = 0
            while not self.state.mavlink_stop_event.is_set():
                msg = self.state.mavlink_connection.recv_match(blocking=False)
                if msg:
                    msg_dict = msg.to_dict()
                    message_count += 1
                    with self.state.mavlink_message_lock:
                        self.state.mavlink_messages.append(msg_dict)
                    
                    self.socketio.emit('mavlink_message', msg_dict, namespace='/mavlink')
                    self.socketio.emit('mavlink_message_count', 
                                     {'count': message_count}, 
                                     namespace='/mavlink')
                else:
                    self.socketio.sleep(0.1)

        except Exception as e:
            print(f"Error in MAVLink listener: {e}")
            self.socketio.emit('mavlink_error', {'message': str(e)}, namespace='/mavlink')
        finally:
            if self.state.mavlink_connection:
                self.state.mavlink_connection.close()
                self.socketio.emit('mavlink_status', {'status': 'Disconnected'}, 
                                 namespace='/mavlink')

    def _toggle_wifi_monitor(self):
        if self.state.wifi_monitoring:
            self.state.stop_capture_event.set()
        else:
            self.state.stop_capture_event.clear()
            self.socketio.start_background_task(self.start_wifi_capture)
        
        self.state.wifi_monitoring = not self.state.wifi_monitoring
        self.socketio.emit("wifi_status", 
                          {"monitoring": self.state.wifi_monitoring}, 
                          namespace="/wifi")
        return "", 204

    def _toggle_mavlink_monitor(self):
        # First, check if there are existing messages that need to be saved
        # This logic is outside the if block to ensure that messages are saved
        # Avoid the MAVLink thread is stopped unexpectedly
        if self.state.mavlink_messages:
            try:
                if filename := self.save_mavlink_messages():
                    print(f"Saved existing messages to {filename}")
                    self.socketio.emit('csv_saved', {'filename': filename}, 
                                        namespace='/mavlink')
                # Clear the messages after saving
                self.state.mavlink_messages.clear()
            except Exception as e:
                error_msg = f'Failed to save existing messages: {e}'
                print(error_msg)
                self.socketio.emit('mavlink_error', 
                                    {'message': error_msg}, 
                                    namespace='/mavlink')
                return 'Failed to save existing messages', 500

        if self.state.mavlink_thread and self.state.mavlink_thread.is_alive():
            self.state.mavlink_stop_event.set()
            self.state.mavlink_thread.join()
            self.state.mavlink_thread = None
        else:
            connection_string = request.get_json().get('connection_string', '').strip()
            if not connection_string:
                return 'Connection string required', 400

            self.state.mavlink_stop_event.clear()
            self.state.mavlink_thread = Thread(
                target=self.mavlink_listener,
                args=(connection_string,)
            )
            self.state.mavlink_thread.start()

        status = ('Connected' if self.state.mavlink_thread and 
                 self.state.mavlink_thread.is_alive() else 'Disconnected')
        self.socketio.emit('mavlink_status',
                          {'monitoring': bool(self.state.mavlink_thread), 
                           'status': status},
                          namespace='/mavlink')
        return '', 204

    def _toggle_monitoring(self):
        connection_string = request.get_json().get("connection_string", "").strip()
        if not connection_string:
            return "Connection string required", 400

        if self.state.wifi_monitoring and (self.state.mavlink_thread and 
                                         self.state.mavlink_thread.is_alive()):
            self.state.stop_capture_event.set()
            self.state.mavlink_stop_event.set()
            if self.state.mavlink_thread:
                self.state.mavlink_thread.join()
            self.state.mavlink_thread = None
            self.state.wifi_monitoring = False
        else:
            self.state.stop_capture_event.clear()
            self.state.mavlink_stop_event.clear()
            self.state.wifi_monitoring = True
            self.socketio.start_background_task(self.start_wifi_capture)
            self.state.mavlink_thread = Thread(
                target=self.mavlink_listener,
                args=(connection_string,)
            )
            self.state.mavlink_thread.start()
        return "", 204

    def _setup_signal_handlers(self):
        def signal_handler(sig, frame):
            print("Gracefully shutting down...")
            self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def cleanup(self):
        """Clean up resources before shutdown"""
        if self.state.wifi_monitoring:
            self.state.stop_capture_event.set()

        if self.state.mavlink_thread and self.state.mavlink_thread.is_alive():
            self.state.mavlink_stop_event.set()
            self.state.mavlink_thread.join()

    def run(self, host="0.0.0.0", port=5001):
        try:
            self.socketio.run(self.app, host=host, port=port)
        except KeyboardInterrupt:
            print("Server interrupted by user. Shutting down...")
            self.cleanup()
            sys.exit(0)

if __name__ == "__main__":
    app = MonitoringApp()
    app.run()