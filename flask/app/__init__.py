#!/usr/bin/env python3
from flask import Flask
from app.models import db
from flask_migrate import Migrate
import app.config
from redis import Redis
import rq

def create_app():
    flask_app = Flask(__name__)
    flask_app.secret_key = b'R@nD-mChang@m3'
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_CONNECTION_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
    flask_app.config['YARA_RULES'] = config.YARA_RULES_FILE_PATH
    flask_app.config['YARA_COMPILED'] = config.YARA_COMPILED_PATH
    flask_app.config['REDIS_URL'] = 'redis://redis:6379'
    flask_app.redis = Redis.from_url(flask_app.config['REDIS_URL'])
    flask_app.task_queue = rq.Queue(connection=flask_app.redis, default_timeout=3600)

    flask_app.app_context().push()
    db.init_app(flask_app)
    # For migrations
    # migrate = Migrate(flask_app, db)
    # migrate.init_app(flask_app, db)
    db.create_all()
    return flask_app