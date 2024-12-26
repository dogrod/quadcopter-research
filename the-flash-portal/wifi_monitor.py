import os
import pyshark
import joblib
import subprocess

from threading import Thread
from time import sleep

import pandas as pd
import numpy as np

from datetime import datetime
from threading import Event, Lock
from collections import deque, defaultdict

from . import socketio
from .config import Config

class IPSegment:
    """Track packet data and metadata for a single IP"""
    def __init__(self, start_time):
        self.packets = []
        self.start_time = start_time
        self.last_update = start_time

class WifiMonitor:
    def __init__(self):
        self.completed_segments = deque()
        self.completed_segments_lock = Lock()
        self.analysis_thread_stop_event = Event()

        self.monitoring = False
        self.stop_capture_event = Event()

        base_dir = os.path.dirname(os.path.abspath(__file__))
        artifacts_path = os.path.join(base_dir, 'ml_models', 'wifi_model_artifacts.pkl')
        artifacts = joblib.load(artifacts_path)
        self.model = artifacts['model']
        self.preprocessor = artifacts['preprocessor']
        self.threshold = artifacts['threshold'] # Add buffer for false positives
        self.segment_duration = artifacts['segment_duration']
        self.time_gap_threshold = artifacts['time_gap_threshold']

        # Start a background thread for analysis
        self.analysis_thread = Thread(target=self.analysis_worker, daemon=True)
        self.analysis_thread.start()

        # IP based segment
        self.ip_segments = defaultdict(lambda: None)
        self.buffer_lock = Lock()

        # Maximum packets per IP segment
        self.max_segment_size = 1000
        
        # Threat tracking
        self.blocked_ips = set()
        self.threat_stats = {
            'low': 0,
            'medium': 0, 
            'high': 0
        }
        self.recent_threats = []
        self.ip_scores = defaultdict(list)
    
    def segment_aggregation(self, df):
        """Aggregate features at segment level matching training exactly"""
        aggs = {
            'frame.len': ['mean','sum','max','min','std'],
            'ip.len': ['mean','sum','max','min','std'],
            'udp.length': ['mean','sum','max','min','std'],
            'eth.src': ['nunique','mean','max','min'],  # Keep all aggs to match training
            'eth.dst': ['nunique','mean','max','min'],  # Keep all aggs to match training
            'ip.src': ['nunique','mean'],
            'ip.dst': ['nunique','mean'],
            'tcp.dstport': ['nunique','mean','max','min'],
            'udp.dstport': ['nunique','mean','max','min'],
            'ip.ttl': ['mean','std'],
            'ip.proto': ['nunique','mean'],
            'tcp.flags.syn': ['sum','mean'],
            'tcp.flags.ack': ['sum','mean'],
            'tcp.flags.fin': ['sum','mean'],
            'tcp.stream': ['nunique','mean'],
            'tcp.srcport': ['nunique','mean','max','min'],
            'udp.srcport': ['nunique','mean','max','min'],
            'protocol_ARP': ['sum','mean'],
            'protocol_TCP': ['sum','mean'],
            'protocol_UDP': ['sum','mean'],
            'protocol_HTTP': ['sum','mean'],
            'protocol_HTTPS': ['sum','mean'],
            'protocol_DNS': ['sum','mean'],
            'protocol_count': ['mean','sum','max','min','std']
        }

        # Convert MAC addresses and IPs to numeric values for aggregation
        df = df.copy()
        for col in ['eth.src', 'eth.dst']:
            df[col] = df[col].apply(lambda x: int(x.replace(':', ''), 16))
        
        # Handle IP addresses
        for col in ['ip.src', 'ip.dst']:
            df[col] = df[col].apply(lambda x: int(''.join([f"{int(n):03d}" for n in x.split('.')])))

        try:
            features = df.groupby('segment_id').agg(aggs)
            # Flatten column names
            features.columns = ['_'.join(col).strip() for col in features.columns.values]
            
            # Verify all required features are present
            expected_features = self.preprocessor.feature_names_in_
            missing_features = set(expected_features) - set(features.columns)
            if missing_features:
                print(f"Warning: Missing features: {missing_features}")
                # Add missing features with 0s
                for feature in missing_features:
                    features[feature] = 0
                    
            # Ensure columns are in same order as training
            features = features.reindex(columns=expected_features, fill_value=0)
            
            return features
            
        except Exception as e:
            print(f"Error in feature aggregation: {e}")
            raise

    def process_packet(self, packet):
        """Extract features from packet matching training data format"""
        try:
            # First check if packet has IP layer
            if not hasattr(packet, 'ip'):
                return None
        
            data = {
                'frame.time_epoch': float(packet.frame_info.time_epoch),
                'frame.len': int(packet.length),
                'eth.src': packet.eth.src if hasattr(packet, 'eth') else '00:00:00:00:00:00',
                'eth.dst': packet.eth.dst if hasattr(packet, 'eth') else '00:00:00:00:00:00',
                'ip.src': packet.ip.src,
                'ip.dst': packet.ip.dst,
                'ip.len': int(packet.ip.len),
                'ip.ttl': int(packet.ip.ttl),
                'ip.proto': int(packet.ip.proto),
                'frame.protocols': str(packet.frame_info.protocols),
            }
            
            # Handle TCP features
            if hasattr(packet, 'tcp'):
                data.update({
                    'tcp.srcport': float(packet.tcp.srcport),
                    'tcp.dstport': float(packet.tcp.dstport),
                    'tcp.flags.syn': float('syn' in packet.tcp.flags),
                    'tcp.flags.ack': float('ack' in packet.tcp.flags),
                    'tcp.flags.fin': float('fin' in packet.tcp.flags),
                    'tcp.stream': float(packet.tcp.stream),
                })
            else:
                data.update({
                    'tcp.srcport': 0,
                    'tcp.dstport': 0,
                    'tcp.flags.syn': 0,
                    'tcp.flags.ack': 0,
                    'tcp.flags.fin': 0,
                    'tcp.stream': 0,
                })

            # Handle UDP features
            if hasattr(packet, 'udp'):
                data.update({
                    'udp.srcport': float(packet.udp.srcport),
                    'udp.dstport': float(packet.udp.dstport),
                    'udp.length': float(packet.udp.length),
                })
            else:
                data.update({
                    'udp.srcport': 0,
                    'udp.dstport': 0,
                    'udp.length': 0,
                })

            # Extract protocols
            protocols = str(packet.frame_info.protocols).split(':')
            data.update({
                'protocol_ARP': float('arp' in protocols),
                'protocol_TCP': float('tcp' in protocols),
                'protocol_UDP': float('udp' in protocols),
                'protocol_HTTP': float('http' in protocols),
                'protocol_HTTPS': float('tls' in protocols or 'ssl' in protocols),
                'protocol_DNS': float('dns' in protocols),
                'protocol_count': len(protocols)
            })

            return data
            
        except AttributeError as e:
            print(f"Error processing packet: {e}")
            return None

    def check_segment_complete(self, segment, current_time):
        """Check if current segment should be closed based on time thresholds"""
        if not segment:
            return False
            
        # Check time gap
        time_inactive = current_time - segment.last_update
        time_total = current_time - segment.start_time

        # Complete if:
        # 1. Inactive for too long, or
        # 2. Total duration exceeded, or
        # 3. Max size reached
        print(f"Time inactive: {time_inactive}, Time total: {time_total}, Packet count: {len(segment.packets)}")
        return (time_inactive > self.time_gap_threshold or
                time_total > self.segment_duration or
                len(segment.packets) > self.max_segment_size)

    def analysis_worker(self):
        while not self.analysis_thread_stop_event.is_set():
            # Sleep for 1 second between analyses
            sleep(1)
            segments_to_analyze = []
            with self.completed_segments_lock:
                # Move all currently queued segments to a local list for analysis
                while self.completed_segments:
                    segments_to_analyze.append(self.completed_segments.popleft())
            
            # Analyze all the completed segments now
            for ip, segment in segments_to_analyze:
                self.analyze_ip_segment(ip, segment)
    
    def analyze_ip_segment(self, ip, segment):
        """Analyze completed segment for specific IP"""
        if not segment.packets:
            print(f"No packets in segment for IP {ip}.")
            return
            
        try:
            # Convert to DataFrame
            df = pd.DataFrame(segment.packets)
            
            # Add segment IDs
            df['segment_id'] = 0
            
            # Aggregate features
            agg_features = self.segment_aggregation(df)
            
            # Verify shape before transform
            if agg_features.shape[1] != len(self.preprocessor.feature_names_in_):
                print(f"Feature mismatch: got {agg_features.shape[1]}, expected {len(self.preprocessor.feature_names_in_)}")
                return
                
            # Preprocess
            X = self.preprocessor.transform(agg_features)
            
            # Score
            score = -self.model.score_samples(X)[0]
            print(f"IP {ip} scored {score}")
            
            # Track score history
            self.ip_scores[ip].append(score)
            if len(self.ip_scores[ip]) > 10:
                self.ip_scores[ip] = self.ip_scores[ip][-10:]
            
            # Calculate average score over recent history
            avg_score = np.mean(self.ip_scores[ip])
            
            # Classify threat level based on consistent behavior
            if avg_score > self.threshold * 0.8:
                threat_level = 'low'

                """Original code"""
                if avg_score > self.threshold:
                    threat_level = 'high' if avg_score > self.threshold * 1.1 else 'medium'

                self.threat_stats[threat_level] += 1
                
                threat_info = {
                    'source_ip': ip,
                    'score': float(avg_score),
                    'threat_level': threat_level,
                    'timestamp': datetime.now().isoformat()
                }
                self.recent_threats.append(threat_info)

                # Block if consistently showing medium threat behavior
                if (threat_level == 'medium' and
                    len(self.ip_scores[ip]) >= 3 and
                    np.mean(self.ip_scores[ip][-3:]) > self.threshold and
                    ip not in self.blocked_ips):
                    self.block_ip(ip, avg_score)
                    
            # Maintain recent threats limit
            if len(self.recent_threats) > 100:
                self.recent_threats = self.recent_threats[-100:]
                
            # Emit updated stats
            self.emit_threat_stats()
            
        except Exception as e:
            print(f"Error analyzing segment for IP {ip}: {e}")
            import traceback
            traceback.print_exc()

    def block_ip(self, ip, score):
        """Block an IP using iptables"""
        try:
            # Check if IP is in whitelist
            if ip in Config.WHITELIST_IPS:
                print(f"IP {ip} is whitelisted, skipping block.")
                return

            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True)
            self.blocked_ips.add(ip)
            
            socketio.emit('ip_blocked', {
                'ip': ip,
                'score': score,
                'timestamp': datetime.now().isoformat()
            }, namespace='/wifi')
            
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")

    def emit_threat_stats(self):
        """Emit current threat statistics"""
        socketio.emit('threat_stats', {
            'threat_counts': self.threat_stats,
            'blocked_ips': list(self.blocked_ips),
            'recent_threats': self.recent_threats
        }, namespace='/wifi')

    def stop_capture(self):
        try:
            # Reset all relevant variables
            self.stop_capture_event.set()
            self.monitoring = False
            self.current_segment = []
            self.segment_start_time = None
            self.blocked_ips = set()
            self.threat_stats = {
                'low': 0,
                'medium': 0,
                'high': 0
            }
            self.recent_threats = []
            self.analysis_thread_stop_event.set()
            self.analysis_thread.join()  # Wait for the analysis thread to stop

            print("Wi-Fi capture closed successfully.")
        except Exception as e:
            print(f"Error while closing Wi-Fi capture: {e}")

    def start_capture(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = f'/data/wifi/ap_traffic_{timestamp}.pcap'

        try:
            capture = pyshark.LiveCapture(
                interface=Config.WIFI_INTERFACE,
                output_file=pcap_filename,
                capture_filter=''
            )

            for packet in capture.sniff_continuously():
                if self.stop_capture_event.is_set():
                    break
                try:
                    packet_data = self.process_packet(packet)
                    if packet_data is None:
                        continue

                    current_time = packet_data['frame.time_epoch']
                    source_ip = packet_data['ip.src']

                    # Only process IP that start with 192.168 and not in whitelist
                    # if source_ip.startswith('192.168') and source_ip not in Config.WIFI_WHITELIST:
                    with self.buffer_lock:
                        # Initialize IP segment if needed
                        ip_segment = self.ip_segments[source_ip]
                        if ip_segment is None:
                            ip_segment = IPSegment(current_time)
                            self.ip_segments[source_ip] = IPSegment(current_time)

                        # Check if current segment should be analyzed
                        if self.check_segment_complete(ip_segment, current_time):
                            # Move the completed segment to the queue
                            with self.completed_segments_lock:
                                self.completed_segments.append((source_ip, ip_segment))

                            # Start a new segment
                            self.ip_segments[source_ip] = IPSegment(current_time)
                            # Reassign ip_segment to the new segment
                            ip_segment = self.ip_segments[source_ip]

                        # Now add the packet to the updated ip_segment
                        ip_segment.packets.append(packet_data)
                        ip_segment.last_update = current_time

                    # Emit package for UI display
                    # print(f"Emitting wifi_packet event: {data}")
                    socketio.emit("wifi_packet", {
                        "source_ip": packet.ip.src,
                        "destination_ip": packet.ip.dst,
                        "protocol": packet.transport_layer,
                        # "info": str(packet),
                        "length": packet.length,
                    }, namespace="/wifi")

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

