#!/usr/bin/env python3
from flask import render_template, request, redirect, flash
from flask import url_for, send_from_directory
from werkzeug.utils import secure_filename
from .models import ApkFile, db
from .codenames import codename
from . import create_app
import hashlib
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
    return render_template('report.html', apk=apk)

if __name__ == "__main__":
    # app.secret_key = os.urandom(24)
    app.run(debug=True, host='0.0.0.0')