#!/usr/bin/env python3
from flask import Flask
# ApkFile is imported below to give acess from >flask shell;from app import ApkFile
from .models import db, ApkFile
from flask_migrate import Migrate
from . import config


def create_app():
    flask_app = Flask(__name__)
    flask_app.secret_key = b'R@nD-mChang@m3'
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_CONNECTION_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
    flask_app.app_context().push()
    db.init_app(flask_app)
    migrate = Migrate(flask_app, db)
    # migrate.init_app(flask_app, db)
    db.create_all()
    return flask_app