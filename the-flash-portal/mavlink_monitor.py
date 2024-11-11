import csv

from datetime import datetime
from pymavlink import mavutil
from threading import Event, Lock

from . import socketio
from .config import Config
from .utils import make_json_serializable

class MAVLinkMonitor:
    def __init__(self):
        self.connection = None
        self.thread = None
        self.stop_event = Event()
        self.messages = []
        self.lock = Lock()
        self.emit_message = False

    def configure_mavlink_streams(self, master):
        # Rate of 10Hz (10 messages per second)
        rate = 10
        streams = [
            # EXT_STAT
            # GPS_STATUS, CONTROL_STATUS, AUX_STATUS
            mavutil.mavlink.MAV_DATA_STREAM_EXTENDED_STATUS,
            # POSITION
            # LOCAL_POSITION, GLOBAL_POSITION/GLOBAL_POSITION_INT
            mavutil.mavlink.MAV_DATA_STREAM_POSITION,
            # Extra 1
            # Attitude data
            mavutil.mavlink.MAV_DATA_STREAM_EXTRA1,
            # Extra 3
            # RANGEFINDER / BATTERY e.t.c.
            mavutil.mavlink.MAV_DATA_STREAM_EXTRA3,
            # Raw sensor data
            mavutil.mavlink.MAV_DATA_STREAM_RAW_SENSORS
        ]

        for stream in streams:
            master.mav.request_data_stream_send(
                master.target_system,
                master.target_component,
                stream,
                rate,
                1
            )

        print("MAVLink streams configured.")

    def listener(self, connection_string):
        try:
            print(f"Attempting to establish MAVLink connection to {connection_string}")
            self.connection = mavutil.mavlink_connection(
                connection_string,
                baud=Config.DEFAULT_BAUD_RATE    
            )
            print(f"Established MAVLink connection to {connection_string}")


            self.configure_mavlink_streams(self.connection)

            print("Waiting for heartbeat from the vehicle...")
            self.connection.wait_heartbeat()
            print("Heartbeat received. Connection established.")
            socketio.emit("mavlink_status", {"status": "Connected"}, namespace="/mavlink")
            
            message_count = 0

            while not self.stop_event.is_set():
                # Listen for MAVLink messages
                msg = self.connection.recv_match(blocking=False)
                if msg:
                    # Convert message to dictionary
                    msg_dict = msg.to_dict()
                    # Add timestamp to message
                    msg_dict['ts'] = datetime.now().isoformat()
                    # print(f"Received MAVLink message: {msg_dict}")
                    message_count += 1
                    self.messages.append(msg_dict)  # Store the message

                    socketio.emit("mavlink_message_count", {"count": message_count}, namespace="/mavlink")
                    # Emit MAVLink message to client
                    if self.emit_message:
                        socketio.emit('mavlink_message', make_json_serializable(msg_dict), namespace='/mavlink')
                else:
                    socketio.sleep(0.1)

        except Exception as e:
            print(f"Error while listening for MAVLink messages: {e}")
            socketio.emit("mavlink_error", {"message": str(e)}, namespace="/mavlink")
        finally:
            print("Closing MAVLink connection...")
            if self.connection:
                self.connection.close()
            print("MAVLink connection closed.")
            socketio.emit("mavlink_status", {"status": "Disconnected"}, namespace="/mavlink")

    def save_messages_to_csv(self):
        with self.lock:
            if not self.messages:
                return None
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            csv_filename = f'/data/mavlink/mavlink_data_{timestamp}.csv'

            try:
                serialized_messages = [make_json_serializable(msg) for msg in self.messages]
                fieldnames = sorted(set().union(*(message.keys() for message in serialized_messages)))
                
                # Use a larger buffer size for better I/O performance
                with open(csv_filename, mode='w', newline='', buffering=8192) as file:
                    writer = csv.DictWriter(file, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(serialized_messages)

                print(f"Successfully saved {len(serialized_messages)} messages to {csv_filename}")
                return csv_filename

            except Exception as e:
                print(f"Error while saving MAVLink messages to CSV: {str(e)}")
                raise



