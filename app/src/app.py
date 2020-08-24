#!/usr/bin/env python3
from flask import render_template, request, redirect, flash
from flask import url_for, send_from_directory, send_file
from werkzeug.utils import secure_filename
from .models import ApkFile, db, DString, Report, YaraMatch, StringPattern
from .codenames import codename
from .processor import prepare_zip_file, run_grep, decompile_apk, analyze_manifest, zipfolder, yara_apk_scan, yara_code_scan
from . import create_app
import hashlib
import yara
import os
import xmltodict
from .commands import db_blueprint

app = create_app()
app.register_blueprint(db_blueprint)

@app.route('/download/sample/<id>')
def download_sample(id):
    apk = ApkFile.query.get(id)
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               "{}.apk".format(id))

@app.route('/download/decompiled/<id>')
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

@app.route('/download/manifest/<id>')
def download_manifest(id):
    apk = ApkFile.query.get(id) 
    return send_file(apk.report.manifest_file_path)


@app.route('/')
def index():
    return render_template('index.html')

### FOR DEVELOPMENT PURPOSES
@app.route('/clear_all')
def clear_db():
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        print('Clear table %s' % table, flush=True)
        db.session.execute(table.delete())
    db.session.commit()
    return redirect('/')

################    
######
# Handle file submitted for analysis
@app.route('/analysis', methods=['POST'])
def analysis():
    if 'file' not in request.files:
            flash('No file part', 'warning')
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
    if request.form.get('get-code-zip'):
        zip_file_path = prepare_zip_file(file_path, decompile_loc)
        new_apk.report.zip_file_path = zip_file_path
    else:
        decompile_apk(file_path, decompile_loc)
    
    analyze_manifest(report, decompile_loc)

    if request.form.get('run-grep-code'):
        run_grep(report, decompile_loc)
    
    if request.form.get('run-yara-apk'):
        yara_apk_scan(new_apk, file_path)

    if request.form.get('run-yara-code'):
        yara_code_scan(new_apk, decompile_loc)

    db.session.commit()
    return redirect('/analysis')

@app.route('/analysis', methods=['GET'])
def dashboard():
    apks = ApkFile.query.order_by(ApkFile.created_at).all()
    return render_template('dashboard.html', apks=apks)

@app.route("/report/<id>/delete", methods=["GET"])
def delete_report(id):
    delete_apk = ApkFile.query.get(id)
    db.session.delete(delete_apk)
    db.session.commit()
    flash('Delete Report Successfuly', 'success')
    return redirect('/anaylsis')

######
# Reports page showing results of analysis
@app.route('/report/<id>', methods=['GET'])
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
    ######
    return render_template('report.html', apk=apk, strings=strings, yara_code_matches=code_matches, yara_apk_matches=apk_matches)

@app.route('/report/<id>/strings', methods=['GET'])
def show_strings(id):
    apk = ApkFile.query.get(id)
    return render_template('strings_show.html', apk=apk)

@app.route('/report/<id>/yara/code/show', methods=['GET'])
def show_yara_code(id):
    apk = ApkFile.query.get(id)
    results = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id,
                YaraMatch.code_scan==True).all()
    return render_template('yara_show.html', apk=apk, matches = results)

@app.route('/report/<id>/yara/apk/show', methods=['GET'])
def show_yara_apk(id):
    apk = ApkFile.query.get(id)
    results = db.session.query(YaraMatch).filter(
                YaraMatch.report_id==apk.report.id,
                YaraMatch.apk_scan==True).all()
    return render_template('yara_show.html', apk=apk, matches = results)

@app.route('/run_yara/<id>', methods=['GET'])
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
    
@app.route('/config/grep', methods=['GET'])
def grep_conf():
    s_patterns = StringPattern.query.all()
    return render_template('grep_conf.html', string_patterns=s_patterns)

if __name__ == "__main__":
    # app.secret_key = os.urandom(24)
    app.run(debug=True, host='0.0.0.0')