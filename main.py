from flask import Flask, request, redirect, url_for, render_template
from flask_basicauth import BasicAuth
from database import *
import string
import random
import passwd
import os

app = Flask(__name__)

basic_auth = BasicAuth(app)

def check(username, password):
    return username == os.getenv('USERNAME') and passwd.check_password_against_stored(password, os.getenv('PASSWORD_HASHED'))

basic_auth.check_credentials = check

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

@app.route('/dashboard')
@basic_auth.required
def dashboard():
    return render_template('dashboard.html', Link=Link, pw=pw, Visit=Visit)

@app.route('/dashboard/create')
@basic_auth.required
def create_link():
    slug = []
    for _ in range(6):
        slug.append(random.choice(string.ascii_letters))
    link = Link.create(
            name="New link",
            description="New link description",
            slug=slug,
            target_url="https://example.com"
        )
    return redirect(url_for('edit_link', id=link.id))

@app.route('/dashboard/edit/<int:id>', methods=['GET', 'POST'])
@basic_auth.required
def edit_link(id):
    link = Link.get_or_none(id=id)
    if not link:
        return "No such link", 404
    if request.method == 'GET':
        return render_template('edit_link.html', link=link, Visit=Visit)
    else:
        link.name = request.form['name']
        link.slug = request.form['slug']
        link.target_url = request.form['target']
        link.description = request.form['description']
        link.save()
        return redirect(url_for('dashboard'))

@app.route('/dashboard/delete-visit/<int:id>', methods=['POST'])
@basic_auth.required
def delete_visit(id):
    visit = Visit.get_or_none(id=id)
    if visit:
        link = visit.link
        visit.delete_instance()
        return redirect(url_for('edit_link', id=link.id))
    else:
        return redirect(url_for('dashboard'))

