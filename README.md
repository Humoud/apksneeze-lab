# APKSNEEZE Lab v0.1

The project is a flask web app which allows doing basic static analysis on Android APK files from a browser.

Current features:
1. Decompile apk files with JADX
2. Zip decompiled files and download them
3. Scan apk file or decompiled code with Yara
4. View in browser specific files that matched a yara rule or download them
4. Grep decompiled files for specific grep patterns
5. Parse/detect permissions and services in manifest files
6. Download manifest files
7. Configure grep patterns and yara rules

## Requirements & Usage

The project runs on docker containers. Make sure you have docker and docker-compose installed:
1. https://docs.docker.com/get-docker/
2. https://docs.docker.com/compose/install/

Run docker compose to build the images and run the project:

`docker-compose -f local.yml up`

Or run it as daemon:

`docker-compose -f local.yml up -d`

Once the docker images are built and the containers are running, two things must be done:

1. Compile yara rules:

`docker-compose -f local.yml exec flask flask apksneeze compile`

2. Seed db (populate grep patterns):

`docker-compose -f local.yml exec flask flask apksneeze seed`

And that's it.

Now you can visit: `http://localhost:5000` to use the app.

If you want to clear the DB (excluding string patterns) you can issue a GET request to path: `/clear_all`

## Modifying Code
You can modify code on the fly since the code volume is mounted  on both the web app and the worker, plus the project is running in debug mode.

## Screenshots

Here are some screenshot of running the tool against the injured android app developed by B3nac https://github.com/B3nac/InjuredAndroid. Many thanks to B3nac for this app!

Index page


![index page](screenshots/index.png)

Dashboard page

![download page](screenshots/dashboard.png)

Report pages:

![report page1](screenshots/report1.png)

![report page2](screenshots/report2.png)

Viewing matched yara rules:

![matched yara rules](screenshots/yara_detected.png)

View code from file with matched a yara rule:

![view code](screenshots/yara_show_code.png)

Yara rules configuration:

![rule configuration](screenshots/yara_conf.png)

Grep patterns configuration:

![grep patterns](screenshots/grep_conf.png)

## Containers
The project uses 4 docker containers:
1. Alpine python (web app)
2. Alpine OpenJDK (worker)
3. Redis
4. Postgres

## Notes
File hashes, apk file sizes, yara rule matches, and grep matches are all stored in a postgresql DB running on one of the docker containers. Also, decompiled files and uploaded apks are stored in the `/storage` directory. The more you use this project, the more data you will accumulate. After that you can get creative with that data.

The worker currenly uses the same code that the flask app is using, perhaps reducing the code and depedencies will result in a lighter image.

## Disclaimer
Just in case: I do not recommend running this in production or on sensitive machines for obvious reasons (look at the code, it can easily be abused). Launch it on a lab/test machine, do analysis, close it.

Usage of APKSneeze Lab for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
