# Quadcopter Research

> This repository contains the research and development of my master degree project. The main goal of this project is to develop a ML model to ensure the security and safety of the quadcopter.

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
