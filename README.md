flask db init

flask db migrate -m "added col or whatever"

flask db upgrade

docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 d2j-dex2jar.sh apksneeze.apk

docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 apkSneeze.py -apk -apk_name apksneeze.apk


TODO

* Add yara
* create strings page
* download csv files of strings
* add quick strings button
* analyze manifest
* download manifest
* compare uploaded apk files
* add analyze immediatly option
* upload multiple apk files
* upload custom yara rules
* upload custom detection strings for grep
* select to run yara against APK for against code
* create jar file
