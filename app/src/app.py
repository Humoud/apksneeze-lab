#!/usr/bin/env python3
from flask import render_template, request, redirect, flash
from flask import url_for, send_from_directory
from werkzeug.utils import secure_filename
from .models import ApkFile, db, DString, Report
from .codenames import codename
from .processor import download_package
from . import create_app
import hashlib
import yara
import os

app = create_app()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

######
# Handle index dashboard page and files submitted for analysis
@app.route('/', methods=['GET','POST'])
def index():
    # Handle new file submissions
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'warning')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'warning')
            return redirect(request.url)
        # if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # save file to disk
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        # calculate file hashes
        with open(file_path, "rb") as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
        # add file name to DB
        new_apk = ApkFile(name=filename,
            md5_hash=md5_hash,
            sha1_hash=sha1_hash,
            sha256_hash=sha256_hash,
            filesize=os.stat(file_path).st_size)
        db.session.add(new_apk)
        db.session.commit()
        return redirect('/')

    else:

        apks = ApkFile.query.order_by(ApkFile.created_at).all()
        return render_template('index.html', apks=apks)

@app.route("/report/<id>/delete", methods=["GET"])
def delete_report(id):
    delete_apk = ApkFile.query.get(id)
    db.session.delete(delete_apk)
    db.session.commit()
    flash('Delete Report Successfuly', 'success')
    return redirect('/')

######
# Reports page showing results of analysis
@app.route('/report/<id>', methods=['GET'])
def show_report(id):
    apk = ApkFile.query.get(id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], apk.name)
    # packages = process_apk(file_path)
    packages =[]
    return render_template('report.html', apk=apk, packages=packages)

@app.route('/report/pkg_download', methods=['POST'])
def pkg_download():
    id = request.form.get('id')
    package = request.form.get('package')
    apk = ApkFile.query.get(id)
    apk_file_path = os.path.join(app.config['UPLOAD_FOLDER'], apk.name)
    download_path = os.path.join(app.config['UPLOAD_FOLDER'], apk.codename.replace(' ','_'))
    # os.mkdir(download_path)
    download_package(apk, package, apk_file_path, download_path)
    # return redirect('/')
    return redirect("/uploads/{}.zip".format(apk.codename.replace(' ','_')))

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

if __name__ == "__main__":
    # app.secret_key = os.urandom(24)
    app.run(debug=True, host='0.0.0.0')