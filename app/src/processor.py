#!/usr/bin/env python3
import subprocess
# import pyjadx
import pathlib
import zipfile
import os

# Processes APK files
# def process_apk(apk_file_path):
#     jadx = pyjadx.Jadx()
#     # decompiler = jadx.load(apk_file_path)
#     # return decompiler.packages
#     return [apk_file_path]

def zipfolder(foldername, target_dir):            
    zipobj = zipfile.ZipFile(foldername + '.zip', 'w', zipfile.ZIP_DEFLATED)
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            zipobj.write(fn, fn[rootlen:])

# Code keep crashing JVM which crashes the container
def download_package(pkg_name, apk_loc, save_loc):
    decompile = subprocess.run(["/jadx/bin/jadx", "-d", save_loc,apk_loc])
    # print("The exit code was: %d" % list_files.returncode)
    # jadx = pyjadx.Jadx(show_inconsistent_code=False)
    # decompiler = jadx.load(apk_loc)
    # try:  
        # for pkg in decompiler.packages:
            # if pkg.fullname.startswith(pkg_name):
                # pkg.save(pathlib.Path(save_loc))
        # zip directory
    zipfolder(save_loc,save_loc)