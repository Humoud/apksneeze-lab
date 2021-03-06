#!/usr/bin/env python3.8
import os

user = os.environ["POSTGRES_USER"]
password = os.environ["POSTGRES_PASSWORD"]
host = os.environ["POSTGRES_HOST"]
database = os.environ["POSTGRES_DB"]
port = os.environ["POSTGRES_PORT"]

DATABASE_CONNECTION_URI = f'postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}'

#  https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
UPLOAD_FOLDER = '/storage'
ALLOWED_EXTENSIONS = {'apk'}
YARA_RULES_FILE_PATH = '/storage/yara_rules/apksneeze.yar'
YARA_COMPILED_PATH = '/storage/yara_rules/compiled_rules'