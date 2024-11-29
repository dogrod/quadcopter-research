from flask import Flask, render_template, request, send_file
import pandas as pd
import numpy as np
import io
from datetime import datetime, timedelta

app = Flask(__name__)

def inject_gps_position_jump(df, jump_size=100):
    """Add sudden position jump to GPS data with consistent changes across all GPS fields"""
    # Find relevant message types
    gps_msgs = df['mavpackettype'].isin(['GPS_RAW_INT', 'GLOBAL_POSITION_INT'])
    if not gps_msgs.any():
        return df
    
    # Select random point for jump
    jump_index = np.random.choice(df[gps_msgs].index)
    
    # Calculate jumps in degrees (scaled appropriately for different fields)
    lat_jump = jump_size / 111111.0  # Converting meters to degrees (approximate)
    lon_jump = lat_jump / np.cos(np.radians(df.loc[jump_index, 'lat'] / 1e7))  # Adjust for latitude
    
    # Apply jumps to all related fields
    for idx in df[df.index >= jump_index].index:
        if df.loc[idx, 'mavpackettype'] in ['GPS_RAW_INT', 'GLOBAL_POSITION_INT']:
            # Position fields
            df.loc[idx, 'lat'] += int(lat_jump * 1e7)
            df.loc[idx, 'latitude'] = df.loc[idx, 'lat'] / 1e7
            df.loc[idx, 'lat_int'] = df.loc[idx, 'lat']
            
            df.loc[idx, 'lon'] += int(lon_jump * 1e7)
            df.loc[idx, 'longitude'] = df.loc[idx, 'lon'] / 1e7
            df.loc[idx, 'lon_int'] = df.loc[idx, 'lon']
            
            # Accuracy metrics
            df.loc[idx, 'h_acc'] *= 1.5  # Increase horizontal accuracy uncertainty
            df.loc[idx, 'v_acc'] *= 1.5  # Increase vertical accuracy uncertainty
            df.loc[idx, 'eph'] *= 1.5    # Increase HDOP
            df.loc[idx, 'epv'] *= 1.5    # Increase VDOP
            
            # Set anomaly label
            df.loc[idx, 'anomaly_label'] = 1
            
    return df

def inject_gps_drift(df, drift_rate=0.1):
    """Add gradual drift to GPS position with consistent changes across related fields"""
    gps_msgs = df['mavpackettype'].isin(['GPS_RAW_INT', 'GLOBAL_POSITION_INT'])
    if not gps_msgs.any():
        return df
    
    # Create time-based drift
    gps_rows = df[gps_msgs]
    times = pd.to_numeric(gps_rows['time_boot_ms'])
    normalized_times = (times - times.min()) / (times.max() - times.min())
    
    for idx in gps_rows.index:
        drift_factor = normalized_times[idx] * drift_rate
        
        # Apply drift to all position fields
        df.loc[idx, 'lat'] += int(drift_factor * 1e7)
        df.loc[idx, 'latitude'] = df.loc[idx, 'lat'] / 1e7
        df.loc[idx, 'lat_int'] = df.loc[idx, 'lat']
        
        df.loc[idx, 'lon'] += int(drift_factor * 1e7)
        df.loc[idx, 'longitude'] = df.loc[idx, 'lon'] / 1e7
        df.loc[idx, 'lon_int'] = df.loc[idx, 'lon']
        
        # Gradually degrade accuracy metrics
        accuracy_factor = 1 + drift_factor
        df.loc[idx, 'h_acc'] *= accuracy_factor
        df.loc[idx, 'v_acc'] *= accuracy_factor
        df.loc[idx, 'eph'] *= accuracy_factor
        df.loc[idx, 'epv'] *= accuracy_factor
        
        # Gradually reduce GPS quality
        df.loc[idx, 'satellites_visible'] = max(4, 
            df.loc[idx, 'satellites_visible'] - int(drift_factor * 3))
            
        # Set anomaly label if drift is significant
        if drift_factor > 0.01:  # Only label if drift is noticeable
            df.loc[idx, 'anomaly_label'] = 1
            
    return df

def inject_rangefinder_noise(df, noise_std=0.5):
    """Add noise to rangefinder readings with consistency checks"""
    rangefinder_rows = df['mavpackettype'] == 'DISTANCE_SENSOR'
    if not rangefinder_rows.any():
        return df
        
    for idx in df[rangefinder_rows].index:
        # Generate noise that respects min/max distance constraints
        current_dist = df.loc[idx, 'current_distance']
        min_dist = df.loc[idx, 'min_distance']
        max_dist = df.loc[idx, 'max_distance']
        
        noise = np.random.normal(0, noise_std * current_dist)  # Scale noise with distance
        new_dist = current_dist + noise
        
        # Ensure we stay within sensor limits
        new_dist = np.clip(new_dist, min_dist, max_dist)
        
        # Update distance and related fields
        df.loc[idx, 'current_distance'] = int(new_dist)
        df.loc[idx, 'signal_quality'] = max(0, df.loc[idx, 'signal_quality'] - 
                                          int(abs(noise) / current_dist * 100))
                                          
        # Update terrain-related fields if present
        if 'terrain_height' in df.columns:
            df.loc[idx, 'terrain_height'] += noise / 2
            df.loc[idx, 'terrain_alt_variance'] *= 1.2
            
        # Set anomaly label if noise is significant
        if abs(noise) > current_dist * 0.1:  # 10% threshold
            df.loc[idx, 'anomaly_label'] = 1
            
    return df

def inject_rangefinder_failure(df, failure_duration=100):
    """Simulate rangefinder failure with consistent effects across related fields"""
    rangefinder_rows = df['mavpackettype'] == 'DISTANCE_SENSOR'
    if not rangefinder_rows.any():
        return df
        
    # Select random point for failure
    failure_start = np.random.choice(df[rangefinder_rows].index[:-failure_duration])
    failure_end = min(failure_start + failure_duration, df.index.max())
    
    failure_indices = df[
        (df.index >= failure_start) & 
        (df.index <= failure_end) & 
        rangefinder_rows
    ].index
    
    for idx in failure_indices:
        # Simulate complete sensor failure
        df.loc[idx, 'current_distance'] = 0
        df.loc[idx, 'signal_quality'] = 0
        
        # Update related fields
        if 'terrain_height' in df.columns:
            df.loc[idx, 'terrain_height'] = np.nan
            df.loc[idx, 'terrain_alt_variance'] = 999999
            
        # Set anomaly label for failure period
        df.loc[idx, 'anomaly_label'] = 1
            
    return df

def inject_imu_interference(df, interference_strength=1.0):
    """Add interference to IMU readings"""
    imu_msgs = df['mavpackettype'].isin(['RAW_IMU', 'SCALED_IMU2'])
    if not imu_msgs.any():
        return df
        
    for idx in df[imu_msgs].index:
        modified = False
        # Add noise to accelerometer readings
        for axis in ['xacc', 'yacc', 'zacc']:
            if axis in df.columns:
                noise = np.random.normal(0, interference_strength * 
                    abs(df.loc[idx, axis]) * 0.1)
                df.loc[idx, axis] += noise
                if abs(noise) > abs(df.loc[idx, axis]) * 0.1:
                    modified = True
        
        # Add noise to gyroscope readings
        for axis in ['xgyro', 'ygyro', 'zgyro']:
            if axis in df.columns:
                noise = np.random.normal(0, interference_strength * 
                    abs(df.loc[idx, axis]) * 0.1)
                df.loc[idx, axis] += noise
                if abs(noise) > abs(df.loc[idx, axis]) * 0.1:
                    modified = True
                    
        # Set anomaly label if significant interference was added
        if modified:
            df.loc[idx, 'anomaly_label'] = 1
                
    return df

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return 'No file uploaded', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No file selected', 400
    
    try:
        # Read CSV file
        df = pd.read_csv(file)
        
        # Initialize anomaly label column
        df['anomaly_label'] = -1
        
        # Get selected anomaly types and parameters
        anomaly_types = request.form.getlist('anomaly_types')
        
        # Apply selected anomalies
        if 'gps_jump' in anomaly_types:
            jump_size = float(request.form.get('jump_size', 100))
            df = inject_gps_position_jump(df, jump_size)
            
        if 'gps_drift' in anomaly_types:
            drift_rate = float(request.form.get('drift_rate', 0.1))
            df = inject_gps_drift(df, drift_rate)
            
        if 'rangefinder_noise' in anomaly_types:
            noise_std = float(request.form.get('noise_std', 0.5))
            df = inject_rangefinder_noise(df, noise_std)
            
        if 'rangefinder_failure' in anomaly_types:
            failure_duration = int(request.form.get('failure_duration', 100))
            df = inject_rangefinder_failure(df, failure_duration)
            
        if 'imu_interference' in anomaly_types:
            interference_strength = float(request.form.get('interference_strength', 1.0))
            df = inject_imu_interference(df, interference_strength)
        
        # Prepare file for download
        output = io.StringIO()
        df.to_csv(output, index=False)
        mem = io.BytesIO()
        mem.write(output.getvalue().encode('utf-8'))
        mem.seek(0)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        download_filename = f'modified_mavlink_{timestamp}.csv'
        
        return send_file(
            mem,
            mimetype='text/csv',
            as_attachment=True,
            download_name=download_filename
        )
        
    except Exception as e:
        return f'Error processing file: {str(e)}', 400

if __name__ == '__main__':
    app.run(debug=True)