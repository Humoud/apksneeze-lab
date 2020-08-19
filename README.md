flask db init

flask db migrate -m "added col or whatever"

flask db upgrade

docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 d2j-dex2jar.sh apksneeze.apk

docker run --rm -v $(pwd):$(pwd) -w "$(pwd)" apk-sneeze1 apkSneeze.py -apk -apk_name apksneeze.apk
