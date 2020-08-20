#!/usr/bin/env python3
import flask_sqlalchemy
from datetime import datetime
from .codenames import codename

db = flask_sqlalchemy.SQLAlchemy()

class ApkFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    codename = db.Column(db.String(80), nullable=False, default=codename)
    analyzed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    report = db.relationship('Report', uselist=False, backref='apk_file')
    md5_hash = db.Column(db.String(32), nullable=False)
    sha1_hash = db.Column(db.String(40), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    filesize = db.Column(db.Integer) # will be in bytes
    def __repr__(self):
        return '<apk %r>' % self.name
    
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apk_file_id = db.Column(db.Integer, db.ForeignKey('apk_file.id'),
        nullable=False)
    package_name = db.Column(db.Text(), nullable=True)
    manifest_file_path = db.Column(db.Text(), nullable=True)
    zip_file_path = db.Column(db.Text(), nullable=True)
    ran_grep = db.Column(db.Boolean, nullable=True, default=False)
    dstrings = db.relationship('DString', backref='report')
    permissions = db.relationship('Permission', backref='report')
    services = db.relationship('Service', backref='report')


# detected string
class DString(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'),
        nullable=False)
    value = db.Column(db.Text(), nullable=False)
    pattern = db.Column(db.Text(), nullable=False)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'),
        nullable=False)
    value = db.Column(db.Text(), nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'),
        nullable=False)
    value = db.Column(db.Text(), nullable=False)
    services = db.relationship('ServiceAttribute', backref='service')

class ServiceAttribute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'),
        nullable=False)
    value = db.Column(db.Text(), nullable=False)