from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/')
def index():
    return 'Link shortener!'

@app.route('/<slug>')
def get_redirect(slug):
    link = Link.get_or_none(slug=slug)
    if not Link:
        return "No such link", 404

    if 'X-Very-Real-IP' in request.headers:
        ip = request.headers['X-Very-Real-IP']
    else:
        ip = request.remote_addr
    Visit.create(link=link, ip_address=ip)
    return redirect(link.target_url)
