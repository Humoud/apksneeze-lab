#!/usr/bin/env python3
import subprocess
import pathlib
import zipfile
import os
from .models import ApkFile, db, DString, Report
import yara

# Processes APK files
# def process_apk(apk_file_path):
#     jadx = pyjadx.Jadx()
#     # decompiler = jadx.load(apk_file_path)
#     # return decompiler.packages
#     return [apk_file_path]

def zipfolder(target_dir):            
    # set zipfile name same as the orignal file but with ext .zip
    zipobj = zipfile.ZipFile(target_dir + '.zip', 'w', zipfile.ZIP_DEFLATED)
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            zipobj.write(fn, fn[rootlen:])

# Code keep crashing JVM which crashes the container
def download_package(apk, pkg_name, apk_loc, save_loc):
    # decompile = subprocess.run(["/jadx/bin/jadx", "-d", save_loc,apk_loc])
    scan_decompiled_code(apk, save_loc)
    # zipfolder(save_loc,save_loc)
############ re-coding
def prepare_zip_file(apk_loc, save_loc):
    # switch -d = --output-dir
    decompile = subprocess.run(["/jadx/bin/jadx","--escape-unicode", "-d",save_loc,apk_loc])
    zipfolder(save_loc)
    # return path of zip file
    return "{}.zip".format(save_loc)


def run_grep(report, code_loc):
    # TODO load patterns from DB
    patterns = ["CTF", "FLAG", "localhost"]
    ds_list = []
    for pattern in patterns:
        command = "grep -nari {} {}/.".format(pattern, code_loc)
        process = subprocess.Popen(command,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # The output from the shell command
        result=process.stdout.readlines()
        for r in result:
            # r = r.decode("utf-8", errors="replace").replace("\x00", "\uFFFD")
            ds = DString(value=r, pattern=pattern)
            report.dstrings.append(ds)
            ds_list.append(ds)
    
    # bulk DB insert
    db.session.add_all(ds_list)
    db.session.commit()
            # ds = DString(value=r, signature="sig")
            # apk.report.dstrings.append(ds)
            # db.session.add(apk)
            # db.session.add(ds)
            # db.session.commit()
############
def scan_decompiled_code(apk, code_location):
    sigs = ["CTF", "FLAG", "localhost"]
    if apk.report == None:
        report = Report(manifest_file="a",jar_file="asd",
                    decompiled_zip_file = "aa",
                    jar_error = True,
                    decompile_error = True)
        apk.report = report
        db.session.add(report)
        db.session.add(apk)
        db.session.commit()
        apk = ApkFile.query.get(apk.id)
    for sig in sigs:
        command = "grep -nari {} {}/.".format(sig, code_location)
        process = subprocess.Popen(command,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # The output from the shell command
        result=process.stdout.readlines()
        for r in result:
            r = r.decode("utf-8", errors="replace").replace("\x00", "\uFFFD")
            ds = DString(value=r, signature="sig")
            apk.report.dstrings.append(ds)
            db.session.add(apk)
            db.session.add(ds)
            db.session.commit()

# def test_yara(files_loc):
#     rules_path = "/storage/yara_rules/"
#     rules = yara.compile(rules_path)
#     matches = []
#     with open(files_loc, 'rb') as f:
#         matches = rules.match(data=f.read())

#     return matches
    # if apk.report.dstrings:
    #     apk.report.dstrings.clear()
    #     db.session.commit()
