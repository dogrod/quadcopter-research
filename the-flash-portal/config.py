class Config:
    WIFI_INTERFACE = "wlan0"
    DEFAULT_BAUD_RATE = 921600
    SOCKET_IO_CONFIG = {
        "async_mode": "threading",
        "cors_allowed_origins": "*",
        "logger": True,
        "engineio_logger": True,
    }

    # Wi-Fi network threat detection
    WIFI_MODEL_PATH = "models/wifi_model.h5"
    WIFI_SCALER_PATH = "models/wifi_scaler.pkl"

    # IP Blocking configuration
    BLOCK_THRESHOLD = 0.8
    WHITELIST_IPS = [
        "192.168.4.4",
        "192.168.4.11"
    ]

    PACKET_BUFFER_SIZE = 100