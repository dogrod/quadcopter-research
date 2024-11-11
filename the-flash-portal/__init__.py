from flask import Flask
from flask_socketio import SocketIO
from .config import Config

app = Flask(__name__)
socketio = SocketIO(app, **Config.SOCKET_IO_CONFIG)