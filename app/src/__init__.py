#!/usr/bin/env python3
from flask import Flask

from .models import db
from . import config


def create_app():
    flask_app = Flask(__name__)
    flask_app.secret_key = b'R@nD-mChang@m3'
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_CONNECTION_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
    flask_app.app_context().push()
    db.init_app(flask_app)
    db.create_all()
    return flask_app