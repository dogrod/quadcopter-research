#!/usr/bin/env python3
import os
import subprocess
from crontab import CronTab
import shutil

def install_dependencies():
    """Install required packages if not already installed."""
    if shutil.which('tshark') is None:
        os.system('sudo apt update')
        os.system('sudo apt install -y tshark cron')
    else:
        print('Dependencies are already installed.')

def setup_auto_start():
    """Set up script to start automatically on login."""
    cron = CronTab(user=True)
    job_command = f'@reboot /usr/bin/python3 {os.path.realpath(__file__)}'
    if not any(job.command == job_command for job in cron):
        job = cron.new(command=job_command, comment='Auto-start Wi-Fi traffic capture on login')
        cron.write()
        print('Auto-start cron job added.')
    else:
        print('Auto-start cron job already exists.')

def capture_wifi_traffic():
    """Capture Wi-Fi traffic and save to a .pcap file."""
    # Define the network interface to capture from (e.g., wlan0)
    interface = 'wlan0'
    # Define the output file for storing the captured data
    pcap_file = '/home/brian/pi/wifi_traffic.pcap'

    # Start the packet capture using tshark
    try:
        subprocess.run(['sudo', 'tshark', '-i', interface, '-w', pcap_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f'Error occurred while running tshark: {e}')

def main():
    # Install dependencies if not already installed
    install_dependencies()
    # Set up auto-start on login using cron
    # setup_auto_start()
    # Capture Wi-Fi traffic data
    capture_wifi_traffic()

if __name__ == '__main__':
    main()