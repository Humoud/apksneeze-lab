#!/usr/bin/env python3
from flask import render_template, request, redirect, flash
from flask import url_for, send_from_directory
from werkzeug.utils import secure_filename
from .models import ApkFile, db, DString, Report
from .codenames import codename
from .processor import prepare_zip_file, run_grep, decompile_apk, analyze_manifest
from . import create_app
import hashlib
import yara
import os
import xmltodict

app = create_app()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
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
    # print(request.form.get('get-code-zip'), flush=True)
    # print(request.form.get('run-yara-apk'), flush=True)
    # print(request.form.get('run-yara-code'), flush=True)
    # print(request.form.get('run-grep-code'), flush=True)

    # if request.form.get('get-code-zip'):
        # zip_file_path = processor.prepare_zip_file(apk_location_on_disk, save_to_location)
    # if request.form.get('run-grep-code'):
        # processor.run_grep(report, code_loc)
    # if request.form.get('run-yara-apk'):
        # processor.yara_scan_apk
    # if request.form.get('run-yara-code'):
        # processor.yara_scan_decompiled_code


    # print(request.form.get('run-grep-code'), flush=True)
    # return redirect('/')
    #############
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
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
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

    # add file name to DB
    new_apk = ApkFile(name=filename,
        md5_hash=md5_hash.hexdigest(),
        sha1_hash=sha1_hash.hexdigest(),
        sha256_hash=sha256_hash.hexdigest(),
        filesize=os.stat(file_path).st_size)
    db.session.add(new_apk)
    db.session.commit()

    # TODO redesign model
    report = Report()
    new_apk.report = report
    db.session.add(report)
    db.session.commit()

    decompile_loc = os.path.join(app.config['UPLOAD_FOLDER'], str(new_apk.id))
    if request.form.get('get-code-zip'):
        zip_file_path = prepare_zip_file(file_path, decompile_loc)
        report.zip_file_path = zip_file_path
    else:
        decompile_apk(file_path, decompile_loc)
    
    analyze_manifest(report, decompile_loc)

    if request.form.get('run-grep-code'):
        run_grep(report, decompile_loc)
    
    db.session.commit()
    print("strings: {}\t\t\tzip file: {}".format(len(new_apk.report.dstrings), new_apk.report.zip_file_path), flush=True)
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
    patterns = [p.pattern for p in db.session.query(DString).filter(DString.report_id==apk.report.id).distinct(DString.pattern).all()]
    strings = []
    for p in patterns:
        c = db.session.query(DString).filter(DString.report_id==4).filter(DString.pattern==p).count()
        strings.append({"pattern": p, "count": c})
    return render_template('report.html', apk=apk, strings=strings)

# @app.route('/report/pkg_download', methods=['POST'])
# def pkg_download():
#     id = request.form.get('id')
#     package = request.form.get('package')
#     apk = ApkFile.query.get(id)
#     apk_file_path = os.path.join(app.config['UPLOAD_FOLDER'], apk.name)
#     download_path = os.path.join(app.config['UPLOAD_FOLDER'], apk.codename.replace(' ','_'))
#     # os.mkdir(download_path)
#     download_package(apk, package, apk_file_path, download_path)
#     # return redirect('/')
#     return redirect("/uploads/{}.zip".format(apk.codename.replace(' ','_')))

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

@app.route('/strings/<id>', methods=['GET'])
def run_strings(id):
    return "a"

if __name__ == "__main__":
    # app.secret_key = os.urandom(24)
    app.run(debug=True, host='0.0.0.0')