#!/usr/bin/env python3.8
from app import create_app
import redis
from rq import Worker, Queue, Connection


app = create_app()
# app.app_context().push()

if __name__ == '__main__':
    with Connection():
        qs = ['default']

        w = Worker(qs, connection=app.redis)
        w.work()