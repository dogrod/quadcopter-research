from flask import Flask
from flask_socketio import SocketIO

from . import app, socketio

# Import routes after app is created
from .routes import api

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5001)