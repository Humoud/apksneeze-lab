#!/usr/bin/env python3
import subprocess
import pathlib
import zipfile
import os
from .models import ApkFile, db, DString, Report, Service, ServiceAttribute, Permission
import yara
import xmltodict
import codecs

# Processes APK files
# def process_apk(apk_file_path):
#     jadx = pyjadx.Jadx()
#     # decompiler = jadx.load(apk_file_path)
#     # return decompiler.packages
#     return [apk_file_path]

def zipfolder(target_dir):            
    # set zipfile name same as the orignal file but with ext .zip
    save_loc = target_dir + '.zip'
    zipobj = zipfile.ZipFile(save_loc, 'w', zipfile.ZIP_DEFLATED)
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            zipobj.write(fn, fn[rootlen:])
    return save_loc

# Code keep crashing JVM which crashes the container
def download_package(apk, pkg_name, apk_loc, save_loc):
    # decompile = subprocess.run(["/jadx/bin/jadx", "-d", save_loc,apk_loc])
    scan_decompiled_code(apk, save_loc)
    # zipfolder(save_loc,save_loc)
############ re-coding

def decompile_apk(apk_loc, save_loc):
    # switch -d = --output-dir
    subprocess.run(["/jadx/bin/jadx","--escape-unicode", "-d",save_loc,apk_loc])

def prepare_zip_file(apk_loc, save_loc):
    decompile_apk(apk_loc, save_loc)
    zip_file_path = zipfolder(save_loc)
    # return path of zip file
    return zip_file_path

def analyze_manifest(report, code_loc):
    perms = []
    svcs = []
    # TODO verify that file exists
    report.manifest_file_path = "{}/resources/AndroidManifest.xml".format(code_loc)
    with open(report.manifest_file_path) as fd:
        doc = xmltodict.parse(fd.read())
        report.package_name = doc['manifest']['@package']
        # permissions
        for p in doc['manifest']['uses-permission']:
            perm = Permission(value=p['@android:name'])
            report.permissions.append(perm)
            perms.append(perm)
        # services
        for key, value in doc['manifest']['application']['service'].items():
            if key == '@android:name':
                svc = Service(value=value)
                report.services.append(svc)
                svcs.append(svc)

    # bulk DB insert
    db.session.add_all(perms)
    db.session.add_all(svcs)
    db.session.commit()

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
            r = r.decode("utf-8", errors="replace").replace("\x00", "\uFFFD")
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

def test_yara(files_loc):
    rules_path = "/storage/yara_rules/apksneeze.yar"
    # compiled_rules = yara.compile(filepaths=rules)

    rules = yara.compile(rules_path)
    rules.save('/storage/yara_rules/compiled_rules')
    rules = yara.load('/storage/yara_rules/compiled_rules')
    matches = []

    for root, dirs, files in os.walk(files_loc):
        for file in files:
            with open(os.path.join(root, file), "rb") as f:
                m = rules.match(data=f.read())
                matches.append(m)
    flat_matches_list = [item for sublist in matches for item in sublist]
    return flat_matches_list
    
    if apk.report.dstrings:
        apk.report.dstrings.clear()
        db.session.commit()
