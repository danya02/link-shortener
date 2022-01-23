from flask import Flask, request, redirect
from database import *
import webauthn

app = Flask(__name__)
app.register_blueprint(webauthn.bp)

@app.before_request
def connect_db():
    db.connect()

@app.after_request
def close_db(response):
    db.close()
    return response


@app.route('/')
def index():
    return 'Link shortener!'

@app.route('/<slug>')
def get_redirect(slug):
    link = Link.get_or_none(slug=slug)
    if not link:
        return "No such link", 404

    if 'X-Very-Real-IP' in request.headers:
        ip = request.headers['X-Very-Real-IP']
    else:
        ip = request.remote_addr
    Visit.create(link=link, ip_address=ip)
    return redirect(link.target_url)



