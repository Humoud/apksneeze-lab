#!/usr/bin/env python3
import flask_sqlalchemy
from datetime import datetime
from app.codenames import codename

db = flask_sqlalchemy.SQLAlchemy()

class ApkFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    codename = db.Column(db.String(80), nullable=False, default=codename)
    ### for rq tasks
    task_id = db.Column(db.Text(), nullable=True)
    analyzed = db.Column(db.Boolean, nullable=True, default=False)
    ###
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    report = db.relationship('Report', uselist=False, lazy='subquery', backref='apk_file')
    md5_hash = db.Column(db.String(32), nullable=True)
    sha1_hash = db.Column(db.String(40), nullable=True)
    sha256_hash = db.Column(db.String(64), nullable=True)
    filesize = db.Column(db.Integer) # will be in bytes
    def __repr__(self):
        return '<apk %r>' % self.name
    
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apk_file_id = db.Column(db.Integer, db.ForeignKey('apk_file.id', ondelete='CASCADE'),
        nullable=True)
    package_name = db.Column(db.Text(), nullable=True)
    manifest_file_path = db.Column(db.Text(), nullable=True)
    zip_file_path = db.Column(db.Text(), nullable=True)
    ran_grep = db.Column(db.Boolean, nullable=True, default=False)
    dstrings = db.relationship('DString', lazy='subquery', backref='report')
    permissions = db.relationship('Permission', lazy='subquery', backref='report')
    services = db.relationship('Service', lazy='subquery', backref='report')
    yara_matches = db.relationship('YaraMatch', lazy='subquery', backref='report')


# detected string
class DString(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id', ondelete='CASCADE'),
        nullable=True)
    value = db.Column(db.Text(), nullable=False)
    pattern = db.Column(db.Text(), nullable=False)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id', ondelete='CASCADE'),
        nullable=True)
    value = db.Column(db.Text(), nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id', ondelete='CASCADE'),
        nullable=True)
    value = db.Column(db.Text(), nullable=False)
    service_attributes = db.relationship('ServiceAttribute', lazy='subquery', backref='service')

class ServiceAttribute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id', ondelete='CASCADE'),
        nullable=True)
    value = db.Column(db.Text(), nullable=False)

class YaraMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apk_scan = db.Column(db.Boolean, nullable=True, default=False)
    code_scan = db.Column(db.Boolean, nullable=True, default=False)
    rule_name = db.Column(db.Text(), nullable=False)
    filename = db.Column(db.Text(), nullable=False)
    # str_offset = db.Column(db.Text(), nullable=True)
    # str_id = db.Column(db.Text(), nullable=True)
    # str_data = db.Column(db.Text(), nullable=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id', ondelete='CASCADE'),
        nullable=True)

class StringPattern(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    pattern = db.Column(db.Text(), nullable=False)
    cmd_switches = db.Column(db.Text(), nullable=False)