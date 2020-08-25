#!/usr/bin/env python3.8
# https://stackoverflow.com/questions/57202736/where-should-i-implement-flask-custom-commands-cli
import click
from flask import Blueprint
import csv
from app.models import db, StringPattern

db_blueprint = Blueprint('seed', __name__)

@db_blueprint.cli.command('db')
# @click.argument('name')
def seed_db():
    """ Seed Database """
    patterns_list=[]
    with open('static/templates/patterns.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1
            else:
                # line_count += 1
                print("Adding Grep pattern: {}".format(row[0]))
                sp = StringPattern(name=row[0],pattern=row[1],cmd_switches=row[2])
                patterns_list.append(sp)
    
    db.session.add_all(patterns_list)
    db.session.commit()


