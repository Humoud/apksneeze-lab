FROM python:3.8.5-alpine3.12
ENV JADX_VERSION=1.1.0 \
    APKTOOL_VERSION=2.4.1 \
    FLASK_APP=app.py \
    FLASK_RUN_PORT=5000 \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_ENV=development

COPY requirements.txt .
COPY flask/ /flask

RUN apk update \
    && apk add --no-cache --virtual build-deps gcc python3-dev musl-dev\
    # postgresql, python3, and pip for flask app
    && apk add postgresql-dev\
    && pip install -r requirements.txt \
    # Cleanup
    && apk del build-deps && rm -rf /var/cache/apk/*

WORKDIR /flask/app

CMD [ "python", "-m", "flask", "run" ]
