import csv
import datetime
import pyshark

from threading import Thread, Event
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from pymavlink import mavutil

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*", logger=True, engineio_logger=True)

# Global variables
# Wi-Fi
wifi_monitoring = False
stop_capture_event = Event()

# MAVLink
mavlink_connection = None
mavlink_thread = None
mavlink_stop_event = Event()
mavlink_messages = []

# Configuration
WIFI_INTERFACE = "wlan0"

# Wi-Fi packet processing
def start_wifi_capture():
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_filename = f'/data/wifi/ap_traffic_{timestamp}.pcap'

    capture = pyshark.LiveCapture(interface=WIFI_INTERFACE, output_file=pcap_filename)

    try:
        for packet in capture.sniff_continuously():
            if stop_capture_event.is_set():
                break
            try:
                data = {
                    "source_ip": packet.ip.src,
                    "destination_ip": packet.ip.dst,
                    "protocol": packet.transport_layer,
                    "info": str(packet),
                    "length": packet.length,
                }
                print(f"Emitting wifi_packet event: {data}")
                socketio.emit("wifi_packet", data, namespace="/wifi")
                socketio.sleep(0.1)
            except AttributeError:
                # Some packets may not have IP layer
                continue
    except Exception as e:
        print(f"Error during packet capture: {e}")
        socketio.emit('error', {'message': str(e)}, namespace='/wifi')
    finally:
        capture.close()
        print(f"Stopped Wi-Fi capture. Saved to {pcap_filename}")
        # Notify the client that the capture has been saved
        socketio.emit('capture_saved', {'filename': pcap_filename}, namespace='/wifi')

# MAVLink message processing
def mavlink_listener(connection_string):
    global mavlink_connection, mavlink_messages

    try:
        # Establish MAVLink connection
        print(f"Attempting to establish MAVLink connection to {connection_string}")
        mavlink_connection = mavutil.mavlink_connection(connection_string, baud=921600)
        print(f"Established MAVLink connection to {connection_string}")
        
        # Wait for heartbeat to ensure connection is established
        print("Waiting for heartbeat...")
        mavlink_connection.wait_heartbeat()
        print("Heartbeat received. Connection successful.", mavlink_connection.target_system, mavlink_connection.target_component)
        socketio.emit('mavlink_status', {'status': 'Connected'}, namespace='/mavlink')
        
        while not mavlink_stop_event.is_set():
            # Listen for MAVLink messages
            msg = mavlink_connection.recv_match(blocking=False)
            if msg:
                # Convert message to dictionary
                msg_dict = msg.to_dict()
                print(f"Received MAVLink message: {msg_dict}")
                mavlink_messages.append(msg_dict)  # Store the message
                # Emit MAVLink message to client
                socketio.emit('mavlink_message', msg_dict, namespace='/mavlink')
            else:
                socketio.sleep(0.1)
    except Exception as e:
        print(f"Error in MAVLink listener: {e}")
        socketio.emit('mavlink_error', {'message': str(e)}, namespace='/mavlink')
    finally:
        if mavlink_connection:
            mavlink_connection.close()
            print("MAVLink connection closed.")
            socketio.emit('mavlink_status', {'status': 'Disconnected'}, namespace='/mavlink')

def save_mavlink_to_csv():
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"/data/mavlink/mavlink_data_{timestamp}.csv"

    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=mavlink_messages[0].keys())
        writer.writeheader()
        writer.writerows(mavlink_messages)

    print(f"MAVLink messages saved to {filename}")
    return filename

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
    global wifi_monitoring, stop_capture_event

    if wifi_monitoring:
        # Stop Wi-Fi monitoring
        print("Stopping Wi-Fi monitoring...")
        stop_capture_event.set()
        wifi_monitoring = False
    else:
        # Start Wi-Fi monitoring
        print("Starting Wi-Fi monitoring...")
        stop_capture_event.clear()
        wifi_monitoring = True
        # Start the packet capture in a new thread with application context
        socketio.start_background_task(start_wifi_capture)

    socketio.emit("wifi_status", {"monitoring": wifi_monitoring}, namespace="/wifi")
    return ("", 204)

@app.route('/toggle_mavlink_monitor', methods=['POST'])
def toggle_mavlink_monitor():
    global mavlink_thread, mavlink_stop_event
    if mavlink_thread and mavlink_thread.is_alive():
        # Stop MAVLink monitoring
        print("Stopping MAVLink monitoring...")
        mavlink_stop_event.set()
        mavlink_thread.join()
        mavlink_thread = None
        mavlink_stop_event.clear()

        # Save messages to CSV
        filename = save_mavlink_to_csv()
        socketio.emit('csv_saved', {'filename': filename}, namespace='/mavlink')
    else:
        # Start MAVLink monitoring
        data = request.get_json()
        connection_string = data.get('connection_string', '').strip()
        if not connection_string:
            return ('Connection string is required', 400)
        print(f"Starting MAVLink monitoring with connection string: {connection_string}")
        mavlink_thread = Thread(target=mavlink_listener, args=(connection_string,))
        mavlink_thread.start()
    return ('', 204)

# Combined Monitoring Logic (Start/Stop Both)
@app.route("/toggle_monitoring", methods=["POST"])
def toggle_monitoring():
    global wifi_monitoring

    if wifi_monitoring and (mavlink_thread and mavlink_thread.is_alive()):
        # Stop both monitors
        print("Stopping both Wi-Fi and MAVLink monitoring...")
        stop_capture_event.set()
        mavlink_stop_event.set()
        if mavlink_thread:
            mavlink_thread.join()
        mavlink_thread = None
        wifi_monitoring = False
    else:
        # Start both monitors
        print("Starting both Wi-Fi and MAVLink monitoring...")
        stop_capture_event.clear()
        mavlink_stop_event.clear()
        wifi_monitoring = True
        socketio.start_background_task(lambda: start_wifi_capture())

        # Start MAVLink monitoring with default connection (or adjust as needed)
        connection_string = request.get_json().get("connection_string", "").strip()
        if not connection_string:
            return ("Connection string is required", 400)
        mavlink_thread = Thread(target=mavlink_listener, args=(connection_string,))
        mavlink_thread.start()
    return ("", 204)

# SocketIO Namespaces
@socketio.on("connect", namespace="/wifi")
def wifi_connect():
    print("Wi-Fi client connected")
    emit("wifi_status", {"monitoring": wifi_monitoring})

@socketio.on("connect", namespace="/mavlink")
def mavlink_connect():
    print("MAVLink client connected")
    status = 'Connected' if mavlink_thread and mavlink_thread.is_alive() else 'Disconnected'
    emit('mavlink_status', {'status': status})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)
