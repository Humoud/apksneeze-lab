FROM openjdk:15-jdk-slim-buster
ENV DEX2JAR_VERSION=2.0 \
    APKTOOL_VERSION=2.4.1 \
    FLASK_APP=app.py \
    FLASK_RUN_PORT=5000 \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_ENV=development

COPY requirements.txt .

RUN apt update \
    # psycopg2 dependencies
    && apt install build-essential git cmake wget unzip -y \
    # postgresql, python3, and pip for flask app
    && apt install python3 python3-pip libpq-dev python3-dev -y\
    ## Dex2Jar or jadx # 
    && wget https://github.com/skylot/jadx/releases/download/v1.1.0/jadx-1.1.0.zip -O /tmp/jadx-1.1.0.zip \
    && unzip /tmp/jadx-1.1.0.zip -d /jadx/ && chmod +x /jadx/bin/* \
    # && wget https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-${DEX2JAR_VERSION}.zip -O /tmp/dex2jar-${DEX2JAR_VERSION}.zip \
    # && unzip /tmp/dex2jar-${DEX2JAR_VERSION}.zip -d /tmp/ \
    # && mv /tmp/dex2jar-${DEX2JAR_VERSION}/* /usr/local/bin/ \
    # && chmod a+x /usr/local/bin/*.sh \
    ## APKTool
    # && wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    # && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar -O /usr/local/bin/apktool.jar \
    # && chmod +x /usr/local/bin/apktool.jar /usr/local/bin/apktool \
    # Python requirements.txt
    && python3 -m pip install -r requirements.txt \
    # Install pyjadx
    # && git clone https://github.com/romainthomas/pyjadx.git /tmp/pyjadx \
    # && cd /tmp/pyjadx && python3 ./setup.py install \
    # Cleanup
    && apt -y clean && apt -y autoremove --purge && rm -rf /tmp/*

WORKDIR /app

CMD [ "python3", "-m", "flask", "run" ]
