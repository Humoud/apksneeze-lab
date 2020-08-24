#!/usr/bin/env python3
import subprocess
import pathlib
import zipfile
import os
from .models import ApkFile, db, DString, Report, Service, ServiceAttribute, Permission, YaraMatch, StringPattern
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
    s_patterns = StringPattern.query.all()
    ds_list = []
    for sp in s_patterns:
        command = "grep {} {} {}/.".format(sp.cmd_switches, sp.pattern, code_loc)
        process = subprocess.Popen(command,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # The output from the shell command
        result=process.stdout.readlines()
        for r in result:
            r = r.decode("utf-8", errors="replace").replace("\x00", "\uFFFD")
            ds = DString(value=r, pattern=sp.name)
            report.dstrings.append(ds)
            ds_list.append(ds)
    
    # bulk DB insert
    db.session.add_all(ds_list)
    db.session.commit()
############
def yara_code_scan(apk, files_loc):
    rules_path = "/storage/yara_rules/apksneeze.yar"
    # compiled_rules = yara.compile(filepaths=rules)

    rules = yara.compile(rules_path)
    rules.save('/storage/yara_rules/compiled_rules')
    rules = yara.load('/storage/yara_rules/compiled_rules')
    matches = []

    for root, dirs, files in os.walk(files_loc):
        for file in files:
            with open(os.path.join(root, file), "rb") as f:
                match = rules.match(data=f.read())
                for m in match:
                    ym = YaraMatch(rule_name=m.rule,code_scan=True,
                                filename=os.path.join(root, file))
                    matches.append(ym)
                    apk.report.yara_matches.append(ym)

    db.session.add_all(matches)
    db.session.commit()
    # flat_matches_list = [item for sublist in matches for item in sublist]
    # return flat_matches_list

def yara_apk_scan(apk, apk_loc):
    rules_path = "/storage/yara_rules/apksneeze.yar"
    # compiled_rules = yara.compile(filepaths=rules)

    rules = yara.compile(rules_path)
    rules.save('/storage/yara_rules/compiled_rules')
    rules = yara.load('/storage/yara_rules/compiled_rules')
    matches = []

    with open(apk_loc, "rb") as f:
        match = rules.match(data=f.read())
        for m in match:
            ym = YaraMatch(rule_name=m.rule,apk_scan=True,
                        filename=apk_loc)
            matches.append(ym)
            apk.report.yara_matches.append(ym)

    db.session.add_all(matches)
    db.session.commit()