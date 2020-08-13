import os

user = os.environ["POSTGRES_USER"]
password = os.environ["POSTGRES_PASSWORD"]
host = os.environ["POSTGRES_HOST"]
database = os.environ["POSTGRES_DB"]
port = os.environ["POSTGRES_PORT"]

DATABASE_CONNECTION_URI = f'postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}'
# from server import db
# from server import APK
# db.create_all()
# obj = APK(name='client1.apk')
# db.session.add(obj)
# db.session.commit()
# obj = APK(name='client2.apk')
# db.session.add(obj)
# db.session.commit()
# obj = APK(name='client3.apk')
# db.session.add(obj)
# db.session.commit()
