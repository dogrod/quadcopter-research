class Config:
    WIFI_INTERFACE = "wlan0"
    DEFAULT_BAUD_RATE = 921600
    SOCKET_IO_CONFIG = {
        "async_mode": "threading",
        "cors_allowed_origins": "*",
        "logger": True,
        "engineio_logger": True,
    }