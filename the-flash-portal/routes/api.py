from threading import Thread
from flask import render_template, request
from flask_socketio import emit

from .. import app, socketio
from ..wifi_monitor import WifiMonitor
from ..mavlink_monitor import MAVLinkMonitor

wifi_monitor = WifiMonitor()
mavlink_monitor = MAVLinkMonitor()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/wifi")
def wifi():
    return render_template("wifi.html")

@app.route("/mavlink")
def mavlink():
    return render_template("mavlink.html")

@app.route("/toggle_wifi_monitoring", methods=["POST"])
def toggle_wifi_monitor():
    if wifi_monitor.monitoring:
        print("Stopping wifi monitoring...")
        wifi_monitor.stop_capture_event.set()
        wifi_monitor.monitoring = False
    else:
        print("Starting wifi monitoring...")
        wifi_monitor.stop_capture_event.clear()
        wifi_monitor.monitoring = True
        socketio.start_background_task(wifi_monitor.start_capture)

    socketio.emit("wifi_status",
                  {"monitoring": wifi_monitor.monitoring},
                  namespace="/wifi")
    
    return ("", 204)

@app.route("/toggle_mavlink_monitor", methods=["POST"])
def toggle_mavlink_monitor():
    # Check if mavlink_message list is not empty
    if mavlink_monitor.messages:
        # Save messages to CSV
        try:
            filename = mavlink_monitor.save_messages_to_csv()
            if filename:
                socketio.emit("csv_saved",
                              {"filename": filename},
                              namespace="/mavlink")

            # Clear the messages list
            mavlink_monitor.messages.clear()
        except Exception as e:
            print(f"Error saving MAVLink messages: {str(e)}", 500)
            socketio.emit("mavlink_error",
                          {"message": f"Failed to save existing messages{str(e)}"},
                          namespace="/mavlink")
    
    if mavlink_monitor.thread and mavlink_monitor.thread.is_alive():
        # Stop MAVLink monitoring
        print("Stopping MAVLink monitoring...")
        mavlink_monitor.stop_event.set()
        mavlink_monitor.thread.join()
        mavlink_monitor.thread = None
        mavlink_monitor.stop_event.clear()
        mavlink_monitor.emit_message = False
    else:
        # Start MAVLink monitoring
        data = request.get_json()
        connection_string = data.get("connection_string", "").strip()
        if not connection_string:
            return ("Connection string is required", 400)

        mavlink_monitor.emit_message = data.get("emit_message", False)

        print(f"Starting MAVLink monitoring with connection string: {connection_string}")
        mavlink_monitor.stop_event.clear()
        mavlink_monitor.thread = Thread(
            target=mavlink_monitor.listener,
            args=(connection_string,)
        )
        mavlink_monitor.thread.start()

    # Determine the current status after toggling
    status = "Connected" if mavlink_monitor.thread and mavlink_monitor.thread.is_alive() else "Disconnected"
    monitoring_state = bool(mavlink_monitor.thread)

    # Emit the updated status to the client
    socketio.emit("mavlink_status",
                  {"monitoring": monitoring_state, "status": status},
                  namespace="/mavlink")
    
    return ("", 204)

@socketio.on("connect", namespace="/wifi")
def wifi_connect():
    print("Wi-Fi client connected")
    emit("wifi_status", {"monitoring": wifi_monitor.monitoring})

@socketio.on("connect", namespace="/mavlink")
def mavlink_connect():
    print("MAVLink client connected")
    status = 'Connected' if (mavlink_monitor.thread and mavlink_monitor.thread.is_alive()) else 'Disconnected'
    emit('mavlink_status', {'status': status})