#!/usr/bin/env python3.8
from flask import Flask
from . import create_app
from app.commands import db_blueprint
flask_app = create_app()
from app.views import views

flask_app.register_blueprint(db_blueprint)
flask_app.register_blueprint(views)

if __name__ == "__main__":
    # app.secret_key = os.urandom(24)
    flask_app.run(debug=True, host='0.0.0.0')