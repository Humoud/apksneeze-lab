#!/usr/bin/env python3.8
from flask import render_template, request, redirect, flash, Blueprint
from flask import url_for, send_from_directory, send_file
from werkzeug.utils import secure_filename
from app.models import *
from app.codenames import codename
from app.processor import file_submission_task, zipfolder
from app.app import flask_app as app
import hashlib
import yara
import os
from io import StringIO
import xmltodict
import csv

views = Blueprint('views', __name__)


@views.route('/download/sample/<id>')
def download_sample(id):
    apk = ApkFile.query.get(id)
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               "{}.apk".format(id))

@views.route('/download/decompiled/<id>')
def download_zip_file(id):
    apk = ApkFile.query.get(id)
    if apk.report.zip_file_path:
        return send_from_directory(app.config['UPLOAD_FOLDER'],"{}.zip".format(id))
    else:
        # zip file doesnt exists, create it
        decompiled_loc = os.path.join(app.config['UPLOAD_FOLDER'], str(apk.id))
        apk.report.zip_file_path = zipfolder(decompiled_loc)
        db.session.commit()
        return send_from_directory(app.config['UPLOAD_FOLDER'],"{}.zip".format(id))

@views.route('/download/manifest/<id>')
def download_manifest(id):
    apk = ApkFile.query.get(id) 
    return send_file(apk.report.manifest_file_path)

@views.route('/download/patterns_template')
def download_patterns_template():
    return send_file('/storage/patterns.csv')

@views.route('/download/yara_rules')
def download_yara_rules():
    return send_file('/storage/yara_rules/apksneeze.yar')

@views.route('/')
def index():
    return render_template('index.html')

### FOR DEVELOPMENT PURPOSES
# @views.route('/clear_all')
# def clear_db():
#     meta = db.metadata
#     for table in reversed(meta.sorted_tables):
#         print('Clear table %s' % table, flush=True)
#         db.session.execute(table.delete())
#     db.session.commit()
#     return redirect('/')
##########

@views.route("/tasks/<job_key>", methods=['GET'])
def get_results(job_key):
    job = Job.fetch(job_key, connection=app.redis)

    if job.is_finished:
        return "Done", 200
    else:
        return "In progress", 202

################    
######
# Handle file submitted for analysis
@views.route('/analysis', methods=['POST'])
def analysis():
    if 'file' not in request.files:
            flash('No file', 'warning')
            return redirect('/')
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect('/')
    # if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    # save file to disk
    new_apk = ApkFile(name=filename)
    db.session.add(new_apk)
    db.session.commit()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], "{}.apk".format(new_apk.id))
    file.save(file_path)
    # calculate file hashes
    with open(file_path, "rb") as f:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        while chunk := f.read(8192):
            md5_hash.update(chunk) 
            sha1_hash.update(chunk) 
            sha256_hash.update(chunk) 

    new_apk.md5_hash = md5_hash.hexdigest()
    new_apk.sha1_hash = sha1_hash.hexdigest()
    new_apk.sha256_hash = sha256_hash.hexdigest()
    new_apk.filesize = os.stat(file_path).st_size
    report = Report()
    new_apk.report = report
    db.session.add(report)
    db.session.commit()

    decompile_loc = os.path.join(app.config['UPLOAD_FOLDER'], str(new_apk.id))
    ########
    req_info = {
        'apk_id': new_apk.id,
        'file_path': file_path,
        'decompile_loc': decompile_loc,
        'prepare_zipfile': request.form.get('get-code-zip'),
        'grep_code': request.form.get('run-grep-code'),
        'yara_apk': request.form.get('run-yara-apk'),
        'yara_code': request.form.get('run-yara-code')
    }

    job = app.task_queue.enqueue_call(
            func=file_submission_task, args=(req_info,), result_ttl=5000
    )
    new_apk.task_id = job.get_id()
    db.session.commit()
    return redirect('/analysis')

@views.route('/analysis', methods=['GET'])
def dashboard():
    apks = ApkFile.query.order_by(ApkFile.created_at).all()
    return render_template('dashboard.html', apks=apks)

@views.route("/report/<id>/delete", methods=["GET"])
def delete_report(id):
    delete_apk = ApkFile.query.get(id)
    db.session.delete(delete_apk)
    db.session.commit()
    flash('Delete Report Successfully', 'success')
    return redirect('/analysis')

######
# Reports page showing results of analysis
@views.route('/report/<id>', methods=['GET'])
def show_report(id):
    apk = ApkFile.query.get(id)
    patterns = [p.pattern for p in db.session.query(DString).filter(
                                        DString.report_id==apk.report.id
                                    ).distinct(DString.pattern).all()]
    strings = []
    for p in patterns:
        c = db.session.query(DString).filter(
                DString.report_id==apk.report.id
            ).filter(DString.pattern==p).count()
        strings.append({"pattern": p, "count": c})

    code_rules = [m.rule_name for m in db.session.query(YaraMatch).filter(
                                        YaraMatch.report_id==apk.report.id, YaraMatch.code_scan==True 
                                    ).distinct(YaraMatch.rule_name).all()]
    code_matches = []
    for r in code_rules:
        c = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id, YaraMatch.code_scan==True
            ).filter(YaraMatch.rule_name==r).count()
        code_matches.append({"rule_name": r, "count": c})
    apk_rules = [m.rule_name for m in db.session.query(YaraMatch).filter(
                                        YaraMatch.report_id==apk.report.id, YaraMatch.apk_scan==True 
                                    ).distinct(YaraMatch.rule_name).all()]
    apk_matches = []
    for r in apk_rules:
        c = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id, YaraMatch.apk_scan==True
            ).filter(YaraMatch.rule_name==r).count()
        apk_matches.append({"rule_name": r, "count": c})
    
    return render_template('report.html', apk=apk, strings=strings, yara_code_matches=code_matches, yara_apk_matches=apk_matches)

@views.route('/report/<id>/strings', methods=['GET'])
def show_strings(id):
    apk = ApkFile.query.get(id)
    return render_template('strings_show.html', apk=apk)

@views.route('/report/<id>/yara/code/show', methods=['GET'])
def show_yara_code(id):
    apk = ApkFile.query.get(id)
    results = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id,
                YaraMatch.code_scan==True).all()
    return render_template('yara_show.html', apk=apk, matches = results)

@views.route('/report/<id>/yara/apk/show', methods=['GET'])
def show_yara_apk(id):
    apk = ApkFile.query.get(id)
    results = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id,
                YaraMatch.apk_scan==True).all()
    return render_template('yara_show.html', apk=apk, matches = results)

@views.route('/run_yara/<id>', methods=['GET'])
def run_yara(id):
    apk = ApkFile.query.get(id)
    files_loc = os.path.join(app.config['UPLOAD_FOLDER'], apk.codename.replace(' ','_'))
    rules_path = "/storage/yara_rules/apksneeze.yar"
    rules = yara.compile(rules_path)
    scans = []
    for root, dirs, files in os.walk(files_loc):
     for file in files:
        with open(os.path.join(root, file), "rb") as f:
            matches = rules.match(data=f.read())
        scans.append([os.path.join(root, file), matches])
    return render_template('yara.html', apk=apk, yara_scans=scans)
    
@views.route('/config/grep', methods=['GET'])
def grep_conf():
    s_patterns = StringPattern.query.all()
    return render_template('grep_conf.html', string_patterns=s_patterns)

@views.route('/config/grep', methods=['POST'])
def upload_new_grep_patterns():
    if 'file' not in request.files:
            flash('No file', 'warning')
            return redirect('/config/grep')
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect('/config/grep')
    
    # Clear string patterns table
    db.session.query(StringPattern).delete()
    db.session.commit()
    # read new file
    patterns_list = []
    stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_reader = csv.reader(stream, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            line_count += 1
        else:
            # line_count += 1
            sp = StringPattern(name=row[0],pattern=row[1],cmd_switches=row[2])
            patterns_list.append(sp)
    
    db.session.add_all(patterns_list)
    db.session.commit()

    s_patterns = StringPattern.query.all()
    flash('Patterns Updated', 'success')
    return render_template('grep_conf.html', string_patterns=s_patterns)

@views.route('/config/yara', methods=['GET'])
def yara_conf():
    print(app.config['YARA_RULES'], flush=True)
    data = None
    with open(app.config['YARA_RULES'], 'r') as f:
        data = f.read().splitlines()
    return render_template('yara_conf.html', rules=data)

@views.route('/config/yara', methods=['POST'])
def yara_conf_upload():
    if 'file' not in request.files:
            flash('No file', 'warning')
            return redirect('/config/yara')
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect('/config/yara')
    
    file.save(app.config['YARA_RULES'])
    rules = yara.compile(app.config['YARA_RULES'])
    # save compiled rules
    rules.save(app.config['YARA_COMPILED'])

    data = None
    with open(app.config['YARA_RULES'], 'r') as f:
        data = f.read().splitlines()
    
    flash('Rules Updated', 'success')
    return render_template('yara_conf.html', rules=data)
