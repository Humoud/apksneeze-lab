#!/usr/bin/env python3
import flask_sqlalchemy
from datetime import datetime
from .codenames import codename

db = flask_sqlalchemy.SQLAlchemy()

class ApkFile(db.Model):
    __tablename__='apks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    codename = db.Column(db.String(80), nullable=False, default=codename)
    analyzed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

    def __repr__(self):
        return '<apk %r>' % self.name