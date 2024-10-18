import subprocess
import pyshark

from threading import Thread, Event
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from pymavlink import mavutil

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*", logger=True, engineio_logger=True)

# Global variables
wifi_capture_thread = None
mavlink_thread = None
wifi_monitoring = False
mavlink_running = False
stop_capture_event = Event()

# Configuration
WIFI_INTERFACE = "wlan0"
DRONE_IP = "192.168.1.1"
MAVLINK_CONNECTION_STRING = "udpout:127.0.0.1:14550"

# Wi-Fi packet processing
def start_wifi_capture():
    global wifi_monitoring
    capture = pyshark.LiveCapture(
        interface=WIFI_INTERFACE,
        # display_filter=f"ip.addr == {DRONE_IP}",
    )
    for packet in capture.sniff_continuously():
        if stop_capture_event.is_set():
            break
        try:
            data = {
                "source_ip": packet.ip.src,
                "destination_ip": packet.ip.dst,
                "protocol": packet.transport_layer,
                # "info": str(packet),
                "length": packet.length,
            }
            print(f"Emitting wifi_packet event: {data}")
            socketio.emit("wifi_packet", data, namespace="/wifi")
        except AttributeError:
            # Some packets may not have IP layer
            continue
    capture.close()

# MAVLink message processing
def mavlink_listener():
    global mavlink_running
    master = mavutil.mavlink_connection(MAVLINK_CONNECTION_STRING)
    master.wait_heartbeat()
    print("Heartbeat from drone:", master.target_system, master.target_component)

    while mavlink_running:
        try:
            msg = master.recv_match(type="ALL", blocking=True, timeout=1)
            if msg:
                print(msg)

                data = {
                    "message_type": msg.get_type(),
                    "content": msg.to_dict(),
                }
                socketio.emit("mavlink_message", data, namespace="/mavlink")
        except Exception as e:
            print(f"Error in mavlink listener: {e}")
            continue

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/wifi")
def wifi_tab():
    return render_template("wifi.html")

@app.route("/mavlink")
def mavlink_tab():
    return render_template("mavlink.html")

@app.route("/toggle_wifi_monitoring", methods=["POST"])
def toggle_wifi_monitor():
    global wifi_monitoring, wifi_capture_thread, stop_capture_event

    if wifi_monitoring:
        # Stop Wi-Fi monitoring
        stop_capture_event.set()
        wifi_capture_thread.join()
        wifi_monitoring = False
    else:
        # Start Wi-Fi monitoring
        stop_capture_event.clear()
        wifi_monitoring = True
        wifi_capture_thread = Thread(target=start_wifi_capture)
        wifi_capture_thread.start()

    return ("", 204)

@app.route('/toggle_mavlink', methods=['POST'])
def toggle_mavlink():
    global mavlink_running, mavlink_thread
    if mavlink_running:
        mavlink_running = False
    else:
        mavlink_running = True
        mavlink_thread = Thread(target=mavlink_listener)
        mavlink_thread.start()
    return ('', 204)

# SocketIO Namespaces
@socketio.on("connect", namespace="/wifi")
def wifi_connect():
    print("Wi-Fi client connected")
    emit("wifi_status", {"monitoring": wifi_monitoring})

@socketio.on("connect", namespace="/mavlink")
def mavlink_connect():
    print("MAVLink client connected")
    emit("mavlink_status", {"running": mavlink_running})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)
