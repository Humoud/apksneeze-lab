#!/usr/bin/env python3.8
# https://stackoverflow.com/questions/57202736/where-should-i-implement-flask-custom-commands-cli
import click
from flask import Blueprint
import csv
from app.models import db, StringPattern
import app.config as config
import yara

commands_bp = Blueprint('apksneeze', __name__)

@commands_bp.cli.command('seed')
# @click.argument('name')
def seed_db():
    """ Seed Database """
    patterns_list=[]
    with open('/storage/patterns.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1
            else:
                print("Adding Grep pattern: {}".format(row[0]))
                sp = StringPattern(name=row[0],pattern=row[1],cmd_switches=row[2])
                patterns_list.append(sp)
    
    db.session.add_all(patterns_list)
    db.session.commit()

@commands_bp.cli.command('compile')
def compile_yara_rules():
    """ compiled yara rules"""
    print("compiling: {}".format(config.YARA_RULES_FILE_PATH))
    rules = yara.compile(config.YARA_RULES_FILE_PATH)
    print("saving compiled rules to: {}".format(config.YARA_COMPILED_PATH))    
    rules.save(config.YARA_COMPILED_PATH)
    print("done.")
