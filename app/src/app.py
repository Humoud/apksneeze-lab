from flask import render_template, request, redirect
from . import create_app, database
from .models import APK

app = create_app()

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        try:
            database.add_instance(APK,name=name)
            return redirect('/')
        except Exception as e:
            return "{}".format(e)
            # TODO uncomment below and return above
            # return "There was a problem adding new stuff."

    else:
        # apks = database.get_all(APK)
        apks = APK.query.order_by(APK.created_at).all()
        return render_template('index.html', apks=apks)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')