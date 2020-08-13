# Install APKTool and Dex2Jar
# FROM openjdk:15-slim-buster
# ENV DEX2JAR_VERSION 2.0
# ENV APKTOOL_VERSION 2.4.1

# RUN apt update && apt install wget unzip -y
# RUN wget https://nchc.dl.sourceforge.net/project/dex2jar/dex2jar-${DEX2JAR_VERSION}.zip -O /tmp/dex2jar-${DEX2JAR_VERSION}.zip && \
#     unzip /tmp/dex2jar-${DEX2JAR_VERSION}.zip -d /tmp/ && \
#     mv /tmp/dex2jar-${DEX2JAR_VERSION}/* /usr/local/bin/ && \
#     chmod a+x /usr/local/bin/*.sh

# RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool
# RUN wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar -O /usr/local/bin/apktool.jar
# RUN chmod +x /usr/local/bin/apktool.jar /usr/local/bin/apktool

# Install APKSneeze
FROM python:3.8-alpine

RUN apk update \
 # psycopg2 dependencies
&& apk add --virtual build-deps gcc python3-dev musl-dev \
&& apk add postgresql-dev
 
COPY requirements.txt .
RUN pip install -r requirements.txt
WORKDIR /app
ENV FLASK_APP=app.py
ENV FLASK_RUN_PORT=5000
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development
CMD [ "python", "-m", "flask", "run" ]

# Clean-up
# RUN apt -y clean && apt -y autoremove --purge && rm -rf /tmp/*


# docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 d2j-dex2jar.sh apksneeze.apk

# docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 apkSneeze.py -apk -apk_name apksneeze.apk



