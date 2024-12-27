# Enhancing Security and Safety in Quadcopter Drones through Unsupervised Machine Learning

> An unsupervised machine learning based anomaly detection system for drone security monitoring. The system is designed to detect network-based attacks and sensor anomalies in real-time using a custom drone platform.

## Features

- Real-time monitoring of network traffic and sensor data
- Detection of network-based attacks including:
  - Man-in-the-Middle (MITM) attacks
  - Denial of Service (DoS) attacks
  - Port scanning
- Detection of sensor anomalies including:
  - GPS spoofing
  - Rangefinder data manipulation
- Automated response mechanisms for detected threats
- Web-based monitoring interface

## System Requirements

### Hardware

- Pixhawk 6C flight controller
- Raspberry Pi 4B (4GB RAM)
- ESP8266 Wi-Fi module
- Holybro M10 GPS module
- Lightware SF45/B rangefinder
- Power module (Holybro PM02)
- Additional components listed in hardware specification document

### Software

- Raspberry Pi OS (64-bit)
- Python 3.9+
- MAVLink protocol libraries
- QGroundControl
- ArduPilot firmware

## The Flash Portal

### Install Dependencies

Make sure you have Python 3 and pip installed on your environment.

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip tshark
sudo apt-get install libxml2-dev libxslt-dev zlib1g-dev  # Dependencies for pyshark
```

Install the Python packages:

```bash
pip install -r requirements.txt
```

### Permission for tshark

```bash
sudo dpkg-reconfigure wireshark-common
# When prompted, select "Yes" to allow non-superusers to capture packets.

sudo usermod -a -G wireshark $USER
```

### Run the App

```bash
sudo python3 app.py
```

### Access the App

```bash
http://<raspberry-pi-ip>:5000
```
