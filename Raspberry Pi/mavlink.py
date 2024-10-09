import csv
import os
from pymavlink import mavutil
import signal
import sys

# Buffers to store GPS and Rangefinder data
gps_data_buffer = []
rangefinder_data_buffer = []

# File paths
gps_file = 'gps_data.csv'
rangefinder_file = 'rangefinder_data.csv'

# Buffer size to control when data is written to disk
buffer_size = 10

def flush_buffers():
    """Flush data buffers to CSV files."""
    if gps_data_buffer:
        with open(gps_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(gps_data_buffer)
        gps_data_buffer.clear()

    if rangefinder_data_buffer:
        with open(rangefinder_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(rangefinder_data_buffer)
        rangefinder_data_buffer.clear()

def signal_handler(sig, frame):
    """Handle program exit to ensure data is not lost."""
    print('\nFlushing buffers and exiting...')
    flush_buffers()
    sys.exit(0)

def main():
    global gps_data_buffer, rangefinder_data_buffer

    # Establish MAVLink connection to Pixhawk via UART
    connection = mavutil.mavlink_connection('/dev/serial0', baud=921600)

    # Set up CSV files for GPS and Rangefinder data
    if not os.path.exists(gps_file):
        with open(gps_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['time_usec', 'lat', 'lon', 'alt', 'fix_type', 'satellites_visible'])

    if not os.path.exists(rangefinder_file):
        with open(rangefinder_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['distance', 'voltage'])

    print("Waiting for MAVLink messages...")

    while True:
        # Wait for the next message from Pixhawk
        msg = connection.recv_match(blocking=True)

        if msg is None:
            continue

        # Convert the message to a dictionary for easier handling
        msg_dict = msg.to_dict()

        # Sort messages by type and output GPS and rangefinder data
        if msg.get_type() == 'GPS_RAW_INT':
            print("\n--- GPS Data ---")
            print(f"Time (ms): {msg_dict['time_usec']}\nLatitude (degE7): {msg_dict['lat']}\nLongitude (degE7): {msg_dict['lon']}\nAltitude (mm): {msg_dict['alt']}\nFix Type: {msg_dict['fix_type']}\nSatellites Visible: {msg_dict['satellites_visible']}")
            # Add GPS data to buffer
            gps_data_buffer.append([msg_dict['time_usec'], msg_dict['lat'], msg_dict['lon'], msg_dict['alt'], msg_dict['fix_type'], msg_dict['satellites_visible']])

            # Write to CSV if buffer is full
            if len(gps_data_buffer) >= buffer_size:
                flush_buffers()

        elif msg.get_type() == 'RANGEFINDER':
            print("\n--- Rangefinder Data ---")
            print(f"Distance (m): {msg_dict['distance']}\nVoltage (V): {msg_dict['voltage']}")
            # Add Rangefinder data to buffer
            rangefinder_data_buffer.append([msg_dict['distance'], msg_dict['voltage']])

            # Write to CSV if buffer is full
            if len(rangefinder_data_buffer) >= buffer_size:
                flush_buffers()

if __name__ == '__main__':
    # Handle SIGINT (Ctrl+C) to safely flush buffers before exiting
    signal.signal(signal.SIGINT, signal_handler)
    try:
        main()
    except KeyboardInterrupt:
        signal_handler(None, None)