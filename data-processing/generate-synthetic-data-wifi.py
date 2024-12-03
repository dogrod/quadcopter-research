import pandas as pd
import argparse
from datetime import datetime
import random
import numpy as np
import sys
from typing import Optional

class BaseAttackGenerator:
    def __init__(self, input_df: pd.DataFrame, start_time: Optional[float] = None):
        """
        Initialize base attack generator with simple time offset handling
        
        Args:
            input_df: Input DataFrame containing network traffic
            start_time: Optional epoch timestamp to start the attack. If not provided,
                       current timestamp will be used.
        """
        self.input_df = input_df.copy()

        # Add label column to input data (0 = normal traffic)
        if 'label' not in self.input_df.columns:
            self.input_df['label'] = 0
        
        # Calculate time offset based on start_time or current time
        original_start = self.input_df['frame.time_epoch'].min()
        self.start_time = start_time or datetime.now().timestamp()
        
        # Calculate the offset needed to shift all timestamps
        self.time_offset = self.start_time - original_start
        
        # Apply the time offset to all records in input_df
        self.input_df['frame.time_epoch'] = self.input_df['frame.time_epoch'] + self.time_offset
        
        # Initialize NaN columns list
        self.nan_columns = [
            'wlan.fc.type', 'wlan.fc.subtype', 'wlan.sa', 'wlan.da', 
            'wlan.bssid', 'radiotap.channel.freq', 'radiotap.dbm_antsignal',
            'radiotap.datarate'
        ]
        
    def _adjust_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Adjust timestamps by adding the calculated offset
        
        Args:
            df: DataFrame containing network traffic data
            
        Returns:
            DataFrame with adjusted timestamps
        """
        # No need for complex calculations, just add the offset to all timestamps
        df['frame.time_epoch'] = df['frame.time_epoch'] + self.time_offset
        return df
    
    def _generate_ip_address(self) -> str:
        """Generate a random IP address"""
        return '.'.join(str(random.randint(0, 255)) for _ in range(4))
    
    def _preserve_nan_columns(self, packet: pd.Series) -> pd.Series:
        """Ensure specified columns remain NaN"""
        for col in self.nan_columns:
            packet[col] = np.nan
        return packet

class DoSAttackGenerator(BaseAttackGenerator):
    def generate(self, duration_seconds: int = 300) -> pd.DataFrame:
        """Generate DoS attack traffic"""
        target_row = self.input_df[pd.notna(self.input_df['ip.dst'])].sample(n=1).iloc[0]
        
        attack_packets = []
        packet_interval = 0.001  # 1ms between packets
        num_packets = int(duration_seconds * 1000)  # 1000 packets per second
        
        current_time = self.start_time  # Start from the adjusted start time
        seq_num = random.randint(1000000, 9999999)
        
        for _ in range(num_packets):
            packet = target_row.copy()
            # Set attack label
            packet['label'] = 1

            packet['frame.time_epoch'] = current_time

            # Set TCP fields
            packet['tcp.flags'] = 'SYN'
            packet['tcp.seq'] = seq_num
            packet['tcp.ack'] = 0
            packet['tcp.srcport'] = float(random.randint(1024, 65535))
            packet['frame.len'] = 74
            packet['tcp.len'] = float(0)
            
            # Clear UDP fields
            packet['udp.srcport'] = np.nan
            packet['udp.dstport'] = np.nan
            packet['udp.length'] = np.nan
            
            packet = self._preserve_nan_columns(packet)
            attack_packets.append(packet)
            
            current_time += packet_interval
            seq_num += 1
        
        # Combine with input_df (which already has adjusted timestamps)
        attack_df = pd.DataFrame(attack_packets)
        return pd.concat([self.input_df, attack_df], ignore_index=True).sort_values('frame.time_epoch')

class MITMAttackGenerator(BaseAttackGenerator):
    def generate(self) -> pd.DataFrame:
        """
        Generate MITM attack traffic focusing on IP addresses and ports
        """
        mitm_packets = []
        attacker_ip = self._generate_ip_address()
        
        for _, packet in self.input_df.iterrows():
            # Original packet
            original = packet.copy()
            mitm_packets.append(original)
            
            # Only intercept packets with valid IP addresses
            if pd.notna(packet['ip.src']) and pd.notna(packet['ip.dst']):
                # Intercepted packet
                intercepted = packet.copy()
                # Set attack label
                intercepted['label'] = 1
                intercepted['ip.src'] = attacker_ip
                intercepted['frame.time_epoch'] += 0.001  # 1ms delay
                
                # Modify TCP sequence numbers if present
                if pd.notna(packet['tcp.seq']):
                    intercepted['tcp.seq'] = float(random.randint(1000000, 9999999))
                    intercepted['tcp.ack'] = float(random.randint(1000000, 9999999))
                
                # Preserve NaN columns
                intercepted = self._preserve_nan_columns(intercepted)
                
                mitm_packets.append(intercepted)
        
        mitm_df = pd.DataFrame(mitm_packets)
        return self._adjust_timestamps(mitm_df)

class PortScanGenerator(BaseAttackGenerator):
    def generate(self, ports_to_scan: int = 100) -> pd.DataFrame:
        """
        Generate port scanning traffic
        
        Args:
            ports_to_scan: Number of ports to scan
        """
        # Select a target from existing legitimate traffic
        target_row = self.input_df[pd.notna(self.input_df['ip.dst'])].sample(n=1).iloc[0]
        
        scan_packets = []
        current_time = self.start_time
        
        # Generate SYN packets for port scanning
        for port in range(1, ports_to_scan + 1):
            packet = target_row.copy()
            # Set attack label
            packet['label'] = 1
            packet['frame.time_epoch'] = current_time
            
            # Set TCP-specific fields
            packet['tcp.dstport'] = float(port)
            packet['tcp.srcport'] = float(random.randint(49152, 65535))
            packet['tcp.flags'] = 'SYN'
            packet['tcp.seq'] = float(random.randint(1000000, 9999999))
            packet['tcp.ack'] = 0.0
            packet['frame.len'] = 74
            packet['tcp.len'] = 0.0
            
            # Clear UDP fields
            packet['udp.srcport'] = np.nan
            packet['udp.dstport'] = np.nan
            packet['udp.length'] = np.nan
            
            # Preserve NaN columns
            packet = self._preserve_nan_columns(packet)
            
            scan_packets.append(packet)
            current_time += 0.1  # 100ms between scan packets
        
        scan_df = pd.DataFrame(scan_packets)
        return pd.concat([self.input_df, scan_df], ignore_index=True).sort_values('frame.time_epoch')

def main():
    parser = argparse.ArgumentParser(description='Generate synthetic network attack data')
    parser.add_argument('input_file', help='Input CSV file path')
    parser.add_argument('output_file', help='Output CSV file path')
    parser.add_argument('attack_type', choices=['dos', 'mitm', 'portscan'], 
                        help='Type of attack to generate')
    parser.add_argument('--start-time', type=float, 
                        help='Start time in epoch format (default: current time)')
    parser.add_argument('--duration', type=int, default=300,
                        help='Duration of attack in seconds (default: 300)')
    
    args = parser.parse_args()
    
    try:
        # Read input CSV
        input_df = pd.read_csv(args.input_file)
        
        # Create appropriate generator based on attack type
        generators = {
            'dos': DoSAttackGenerator,
            'mitm': MITMAttackGenerator,
            'portscan': PortScanGenerator
        }
        
        generator_class = generators[args.attack_type]
        generator = generator_class(input_df, args.start_time)
        
        # Generate attack data
        if args.attack_type == 'dos':
            result_df = generator.generate(duration_seconds=args.duration)
        elif args.attack_type == 'portscan':
            result_df = generator.generate(ports_to_scan=1000)
        else:
            result_df = generator.generate()
        
        # Save to output file
        result_df.to_csv(args.output_file, index=False)
        print(f"Successfully generated {args.attack_type} attack data in {args.output_file}")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()