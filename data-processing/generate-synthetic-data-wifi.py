import numpy as np
import pandas as pd
from sklearn.utils import shuffle
import datetime
from typing import Dict, List, Union

class ArduPilotConfig:
    """Configuration class for Ardupilot-specific network data generation."""
    def __init__(self):
        # Sample sizes
        self.normal_samples = 10000
        self.attack_samples = {
            'mitm': 500,
            'dos': 500,
            'port_scan': 500
        }
        
        # Ardupilot-specific configurations
        self.mavlink_ports = list(range(14550, 14558))  # 14550-14557
        self.sitl_port = 5760
        self.common_mavlink_size = 280  # typical MAVLink packet size
        self.heartbeat_interval = 1.0  # 1 Hz heartbeat
        
        # Protocol distribution (based on Ardupilot typical traffic)
        self.protocol_dist = {
            'UDP': 0.95,  # Majority UDP for MAVLink
            'TCP': 0.05   # Minimal TCP
        }
        
        # Other configurations
        self.seed = 42
        self.output_file = 'synthetic_ardupilot_network_data.csv'

def generate_frame_data(num_samples: int, packet_size_mean: int = 280, 
                       packet_size_std: int = 30) -> Dict[str, List]:
    """Generate basic frame-level data with MAVLink-like characteristics."""
    return {
        'frame.time_epoch': [datetime.datetime.now().timestamp() + i * 0.001 
                            for i in range(num_samples)],
        'frame.len': np.random.normal(packet_size_mean, packet_size_std, 
                                    num_samples).astype(int),
        'frame.protocols': ['eth:ethertype:ip:udp'] * num_samples,
        '_ws.col.protocol': ['UDP'] * num_samples
    }

def generate_normal_traffic(num_samples: int, config: ArduPilotConfig) -> pd.DataFrame:
    """Generate synthetic normal Ardupilot traffic data."""
    data = pd.DataFrame()
    
    # Generate basic frame data with MAVLink packet sizes
    frame_data = generate_frame_data(num_samples, 
                                   packet_size_mean=config.common_mavlink_size)
    for key, value in frame_data.items():
        data[key] = value
    
    # Network layer features
    data['ip.src'] = [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" 
                      for _ in range(num_samples)]
    data['ip.dst'] = [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" 
                      for _ in range(num_samples)]
    
    # Initialize all fields with NaN
    tcp_fields = ['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.len', 
                 'tcp.stream', 'tcp.seq', 'tcp.ack']
    udp_fields = ['udp.srcport', 'udp.dstport', 'udp.length']
    
    for field in tcp_fields + udp_fields:
        data[field] = pd.NA
    
    # Fill UDP fields for MAVLink traffic
    data['udp.srcport'] = np.random.choice(config.mavlink_ports, num_samples)
    data['udp.dstport'] = np.random.choice(config.mavlink_ports, num_samples)
    data['udp.length'] = data['frame.len'] - 42  # UDP length = frame length - headers
    
    data['label'] = 0  # Normal traffic
    return data

def generate_mitm_attack(num_samples: int, config: ArduPilotConfig) -> pd.DataFrame:
    """Generate synthetic MITM attack data for Ardupilot."""
    data = pd.DataFrame()
    
    # Generate basic frame data
    frame_data = generate_frame_data(num_samples, 
                                   packet_size_mean=config.common_mavlink_size)
    for key, value in frame_data.items():
        data[key] = value
    
    # MITM attack on MAVLink communication
    legitimate_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    attacker_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    
    data['ip.src'] = [legitimate_ip if i % 2 == 0 else attacker_ip 
                      for i in range(num_samples)]
    data['ip.dst'] = [attacker_ip if i % 2 == 0 else legitimate_ip 
                      for i in range(num_samples)]
    
    # Set all TCP fields to NaN
    tcp_fields = ['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.len', 
                 'tcp.stream', 'tcp.seq', 'tcp.ack']
    for field in tcp_fields:
        data[field] = pd.NA
    
    # UDP fields targeting MAVLink ports
    data['udp.srcport'] = np.random.choice(config.mavlink_ports, num_samples)
    data['udp.dstport'] = np.random.choice(config.mavlink_ports, num_samples)
    data['udp.length'] = data['frame.len'] - 42
    
    data['label'] = 1  # MITM attack
    return data

def generate_dos_attack(num_samples: int, config: ArduPilotConfig) -> pd.DataFrame:
    """Generate synthetic DoS attack data targeting Ardupilot."""
    data = pd.DataFrame()
    
    # Generate basic frame data with flood characteristics
    frame_data = generate_frame_data(num_samples, 
                                   packet_size_mean=200,  # Smaller packets for flood
                                   packet_size_std=20)
    for key, value in frame_data.items():
        data[key] = value
    
    # Target specific drone IP and port
    target_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    data['ip.src'] = [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" 
                      for _ in range(num_samples)]
    data['ip.dst'] = [target_ip] * num_samples
    
    # Set all TCP fields to NaN
    tcp_fields = ['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.len', 
                 'tcp.stream', 'tcp.seq', 'tcp.ack']
    for field in tcp_fields:
        data[field] = pd.NA
    
    # UDP flood targeting primary MAVLink port
    data['udp.srcport'] = np.random.randint(1024, 65535, num_samples)
    data['udp.dstport'] = [14550] * num_samples  # Target primary GCS port
    data['udp.length'] = data['frame.len'] - 42
    
    data['label'] = 2  # DoS attack
    return data

def generate_port_scan_attack(num_samples: int, config: ArduPilotConfig) -> pd.DataFrame:
    """Generate synthetic Port Scanning attack targeting Ardupilot ports."""
    data = pd.DataFrame()
    
    # Generate basic frame data for scanning
    frame_data = generate_frame_data(num_samples, 
                                   packet_size_mean=60,  # Small packets for scanning
                                   packet_size_std=5)
    for key, value in frame_data.items():
        data[key] = value
    
    # Targeting drone IP
    target_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
    data['ip.src'] = [f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}" 
                      for _ in range(num_samples)]
    data['ip.dst'] = [target_ip] * num_samples
    
    # Mix of UDP and TCP scanning
    is_tcp = np.random.choice([True, False], num_samples, p=[0.7, 0.3])
    data['_ws.col.protocol'] = ['TCP' if x else 'UDP' for x in is_tcp]
    data['frame.protocols'] = ['eth:ethertype:ip:tcp' if x else 'eth:ethertype:ip:udp' 
                              for x in is_tcp]
    
    # Initialize all fields with NaN
    tcp_fields = ['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.len', 
                 'tcp.stream', 'tcp.seq', 'tcp.ack']
    udp_fields = ['udp.srcport', 'udp.dstport', 'udp.length']
    
    for field in tcp_fields + udp_fields:
        data[field] = pd.NA
    
    # Fill TCP scanning fields
    data.loc[is_tcp, 'tcp.srcport'] = np.random.randint(50000, 60000, sum(is_tcp))
    # Scan relevant ports for Ardupilot
    scan_ports = list(range(14550, 14558)) + [5760] + list(range(1, 1024))
    data.loc[is_tcp, 'tcp.dstport'] = np.random.choice(scan_ports, sum(is_tcp))
    data.loc[is_tcp, 'tcp.flags'] = 'S'  # SYN scan
    data.loc[is_tcp, 'tcp.len'] = 0
    data.loc[is_tcp, 'tcp.stream'] = range(sum(is_tcp))
    data.loc[is_tcp, 'tcp.seq'] = np.random.randint(0, 1000000000, sum(is_tcp))
    data.loc[is_tcp, 'tcp.ack'] = 0
    
    # Fill UDP scanning fields
    is_udp = ~is_tcp
    data.loc[is_udp, 'udp.srcport'] = np.random.randint(50000, 60000, sum(is_udp))
    data.loc[is_udp, 'udp.dstport'] = np.random.choice(scan_ports, sum(is_udp))
    data.loc[is_udp, 'udp.length'] = data.loc[is_udp, 'frame.len'] - 42
    
    data['label'] = 3  # Port Scanning attack
    return data

def main():
    # Initialize configuration
    config = ArduPilotConfig()
    np.random.seed(config.seed)
    
    print("Generating normal traffic...")
    normal_data = generate_normal_traffic(config.normal_samples, config)
    
    print("Generating MITM attack traffic...")
    mitm_data = generate_mitm_attack(config.attack_samples['mitm'], config)
    
    print("Generating DoS attack traffic...")
    dos_data = generate_dos_attack(config.attack_samples['dos'], config)
    
    print("Generating Port Scan attack traffic...")
    port_scan_data = generate_port_scan_attack(config.attack_samples['port_scan'], config)
    
    # Combine all data
    combined_data = pd.concat(
        [normal_data, mitm_data, dos_data, port_scan_data], 
        ignore_index=True
    )
    
    # Shuffle the dataset
    combined_data = shuffle(combined_data, random_state=config.seed).reset_index(drop=True)
    
    # Save to CSV
    combined_data.to_csv(config.output_file, index=False)
    print(f"Synthetic Ardupilot network data has been saved to '{config.output_file}'")
    
    # Print dataset statistics
    print("\nDataset Statistics:")
    print(f"Total samples: {len(combined_data)}")
    print("\nClass distribution:")
    print(combined_data['label'].value_counts().sort_index())
    print("\nProtocol distribution:")
    print(combined_data['_ws.col.protocol'].value_counts())

if __name__ == "__main__":
    main()