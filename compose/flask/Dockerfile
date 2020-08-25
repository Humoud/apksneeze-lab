FROM openjdk:16-jdk-alpine3.12
ENV JADX_VERSION=1.1.0 \
    APKTOOL_VERSION=2.4.1 \
    FLASK_APP=app.py \
    FLASK_RUN_PORT=5000 \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_ENV=development \
    # PACKAGES needed to for psycopg2 and python
    BUILD_PACKAGES="\
        gcc \
        python3-dev \
        musl-dev \
        bzip2-dev \
        coreutils \
        dpkg \
        dpkg-dev \
        expat-dev \
        findutils \
        gcc \
        gdbm-dev \
        libc-dev \
        libffi-dev \
        libnsl-dev \
        libtirpc-dev \
        linux-headers \
        make \
        ncurses-dev \
        libressl-dev \
        pax-utils \
        readline-dev \
        sqlite-dev \
        tcl-dev \
        tk \
        tk-dev \
        util-linux-dev \
        xz-dev \
        zlib-dev \
    "

COPY requirements.txt .
COPY flask/ /flask

RUN apk update \
    && apk add --no-cache --virtual build-deps $BUILD_PACKAGES\
    # postgresql, python3, and pip for flask app
    && apk add postgresql-dev python3 py3-pip\
    && pip install -r requirements.txt \
    # Cleanup
    && apk del build-deps && rm -rf /var/cache/apk/* \
    && chmod +x /flask/run_app.sh

WORKDIR /flask/app

CMD [ "python3.8", "-m", "flask", "run" ]
