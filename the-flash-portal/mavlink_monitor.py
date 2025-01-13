import os
import joblib
import numpy as np
import pandas as pd
import csv

from datetime import datetime, timedelta
from collections import defaultdict, deque
from time import sleep

from pymavlink import mavutil
from threading import Event, Lock, Thread

from . import socketio
from .config import Config
from .utils import make_json_serializable

class SensorSegment:
    """Track sensor data for anomaly detection"""
    def __init__(self, start_time):
        self.messages = []
        self.start_time = start_time
        self.last_update = start_time

class MAVLinkMonitor:
    def __init__(self):
        self.connection = None
        self.thread = None
        self.stop_event = Event()
        self.messages = []
        self.lock = Lock()
        self.emit_message = False
        
        # Anomaly detection components
        self.recent_messages = deque(maxlen=1000)  # Buffer for recent messages
        self.completed_segments = deque()  # Segments ready for analysis
        self.segments_lock = Lock()
        self.anomaly_thread_stop_event = Event()
        
        # Load model artifacts
        base_dir = os.path.dirname(os.path.abspath(__file__))
        artifacts_path = os.path.join(base_dir, 'ml_models', 'mavlink_model_artifacts.pkl')
        self.model_artifacts = joblib.load(artifacts_path)
        
        # Initialize anomaly tracking
        self.anomaly_counts = defaultdict(int)  # Track anomalies per sensor
        self.anomaly_timestamps = defaultdict(list)  # Track anomaly times
        self.anomaly_lock = Lock()
        
        # Start anomaly detection thread
        self.anomaly_thread = Thread(target=self.anomaly_worker, daemon=True)
        self.anomaly_thread.start()
    
    def segment_data(self, messages):
        """Segment messages based on training logic"""
        if not messages:
            return []
            
        df = pd.DataFrame(messages)
        df['ts'] = pd.to_datetime(df['ts'])
        
        # Ensure time order
        df = df.sort_values('ts').reset_index(drop=True)
        
        # Find breaks based on time gaps
        time_diff = df['ts'].diff().dt.total_seconds()
        time_breaks = np.where(time_diff > self.model_artifacts['max_time_diff'])[0]
        
        segments = []
        start_idx = 0
        
        # Create segments
        for break_idx in time_breaks:
            current_segment = df.iloc[start_idx:break_idx]
            while len(current_segment) > self.model_artifacts['max_points']:
                segments.append(current_segment.iloc[:self.model_artifacts['max_points']])
                current_segment = current_segment.iloc[self.model_artifacts['max_points']:]
            
            if not current_segment.empty:
                segments.append(current_segment)
            
            start_idx = break_idx
            
        # Handle final segment
        final_segment = df.iloc[start_idx:]
        while len(final_segment) > self.model_artifacts['max_points']:
            segments.append(final_segment.iloc[:self.model_artifacts['max_points']])
            final_segment = final_segment.iloc[self.model_artifacts['max_points']:]
            
        if not final_segment.empty:
            segments.append(final_segment)
            
        return segments

    def engineer_features(self, df):
        """Generate features for anomaly detection"""
        features = pd.DataFrame()
        
        # GPS speed and movement features
        gps_cols = ['lat', 'lon', 'alt', 'vx', 'vy', 'vz']
        if all(col in df.columns for col in gps_cols):
            # 3D speed
            features['gps_speed_3d'] = np.sqrt(
                df['vx'].fillna(0)**2 + 
                df['vy'].fillna(0)**2 + 
                df['vz'].fillna(0)**2
            )
            
            # Heading stability
            if 'ts' in df.columns and 'hdg' in df.columns:
                features['heading_stability'] = df.groupby(
                    pd.to_datetime(df['ts']).diff().dt.total_seconds().gt(0.5).cumsum()
                )['hdg'].std().fillna(0)
            
            # Height consistency
            if 'relative_alt' in df.columns:
                features['height_consistency'] = np.abs(df['alt'] - df['relative_alt']).fillna(0)
            
            # Position precision
            if 'fix_type' in df.columns:
                features['position_precision'] = df['fix_type'].fillna(0)
        
        # Handle missing/infinite values
        features = features.fillna(0)
        features = features.replace([np.inf, -np.inf], 0)
        
        return features

    def check_anomaly_threshold(self, sensor_id):
        """Check if anomaly threshold is met for given sensor"""
        with self.anomaly_lock:
            # Get timestamps from last 5 seconds
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(seconds=5)
            
            # Filter recent anomalies
            recent_anomalies = [
                ts for ts in self.anomaly_timestamps[sensor_id]
                if ts > cutoff_time
            ]
            
            # Update timestamps list
            self.anomaly_timestamps[sensor_id] = recent_anomalies
            
            return len(recent_anomalies) >= 3

    def send_hold_position(self):
        """Send hold position command to drone"""
        try:
            if self.connection:
                # Send MAVLink command to hold position
                self.connection.mav.command_long_send(
                    self.connection.target_system,
                    self.connection.target_component,
                    mavutil.mavlink.MAV_CMD_NAV_LOITER_UNLIM,
                    0,  # Confirmation
                    0, 0, 0, 0, 0, 0, 0  # Parameters
                )
                print("Sent hold position command")
                
                # Emit event
                socketio.emit('mavlink_hold_position', {
                    'timestamp': datetime.now().isoformat(),
                    'reason': 'sensor_anomaly'
                }, namespace='/mavlink')
                
        except Exception as e:
            print(f"Error sending hold position command: {e}")

    def anomaly_worker(self):
        """Background worker for anomaly detection"""
        while not self.anomaly_thread_stop_event.is_set():
            # Sleep between analyses
            sleep(0.1)
            
            try:
                # Get messages for analysis
                messages_to_analyze = []
                with self.lock:
                    if len(self.recent_messages) >= 50:  # Minimum batch size
                        messages_to_analyze = list(self.recent_messages)
                        self.recent_messages.clear()
                
                if not messages_to_analyze:
                    continue
                    
                # Segment messages
                segments = self.segment_data(messages_to_analyze)
                
                # Analyze each segment
                for segment_df in segments:
                    # Generate features
                    features = self.engineer_features(segment_df)
                    
                    # Skip if no features generated
                    if features.empty:
                        continue
                    
                    # Make prediction
                    score = self.model_artifacts['model'].score_samples(features)
                    
                    # Check for anomalies
                    if score < self.model_artifacts['threshold']:
                        # Track anomaly
                        sensor_id = 'gps'  # Simplified for example
                        
                        with self.anomaly_lock:
                            self.anomaly_counts[sensor_id] += 1
                            self.anomaly_timestamps[sensor_id].append(datetime.now())
                        
                        # Emit anomaly event
                        socketio.emit('mavlink_anomaly', {
                            'sensor': sensor_id,
                            'score': float(score),
                            'threshold': float(self.model_artifacts['threshold']),
                            'timestamp': datetime.now().isoformat()
                        }, namespace='/mavlink')
                        
                        #! This code is commented out to prevent accidental drone commands
                        #! Please uncomment if you want to test, and ensure safety measures are in place
                        # Check threshold and send command if needed
                        # if self.check_anomaly_threshold(sensor_id):
                        #     self.send_hold_position()
                
            except Exception as e:
                print(f"Error in anomaly detection: {e}")
                continue

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

                    with self.lock:
                        self.messages.append(msg_dict)  # Store for CSV export
                        #! Uncomment this line to enable anomaly detection
                        # self.recent_messages.append(msg_dict)  # Store for anomaly detection

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
