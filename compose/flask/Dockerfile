FROM openjdk:16-jdk-alpine3.12
ENV JADX_VERSION=1.1.0 \
    APKTOOL_VERSION=2.4.1 \
    FLASK_APP=app.py \
    FLASK_RUN_PORT=5000 \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_ENV=development

COPY requirements.txt .

RUN apk update \
    # psycopg2 dependencies
    && apk add --virtual build-deps g++ autoconf build-base binutils file libgcc libtool linux-headers ninja tar libstdc++ gcc make cmake git python3-dev musl-dev wget unzip \
    # postgresql, python3, and pip for flask app
    && apk add postgresql-dev python3 py3-pip\
    # YARA
    # && apk add yara\
    ## Dex2Jar or jadx # 
    && wget https://github.com/skylot/jadx/releases/download/v1.1.0/jadx-${JADX_VERSION}.zip -O /tmp/jadx-${JADX_VERSION}.zip \
    && unzip /tmp/jadx-${JADX_VERSION}.zip -d /jadx/ && chmod +x /jadx/bin/* \
    && pip install -r requirements.txt \
    # Install pyjadx
    # && git clone https://github.com/romainthomas/pyjadx.git /tmp/pyjadx \
    # && cd /tmp/pyjadx && python3 ./setup.py install \
    # Cleanup
    && apk del build-deps && rm -rf /var/cache/apk/*

WORKDIR /app

CMD [ "python3.8", "-m", "flask", "run" ]
