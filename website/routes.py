import time
from flask import Blueprint, request, session, url_for
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth


bp = Blueprint('home', __name__)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/oauth/', methods=('GET', 'POST'))
def home():
    print("route /oauth/")
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/oauth/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('home.html', user=user, clients=clients)


@bp.route('/oauth/logout')
def logout():
    print("route /logout")
    del session['id']
    return redirect('/oauth/')


@bp.route('/oauth/create_client', methods=('GET', 'POST'))
def create_client():
    print("route /create_client")
    user = current_user()
    if not user:
        return redirect('/oauth/')
    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect('/oauth/')

def read_public_key_file(path):
    with open(path, 'r') as f:
        key = f.read()
    # Rimuovi le intestazioni e le interruzioni di riga
    #key = key.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
    return key

@bp.route('/oauth/certs', methods=['GET'])
def certs():
    import json

    #with open('jwks.json', 'r') as f:
    #    jwks = json.load(f)
    #return jsonify(jwks)
    from authlib.jose import JsonWebKey, jwt

    key_data = read_public_key_file('public_key.pem')
    tmp_key = JsonWebKey.import_key(key_data, {'kty': 'RSA', 'kid': 'TEMP_KEY'})   # just to compute the thumbprint
    key = JsonWebKey.import_key(tmp_key.as_bytes(), {'kty': 'RSA', 'alg': 'RS256', 
                                                        'use': 'sig', 'ext': True,
                                                        'kid': tmp_key.thumbprint()})

    # Devi formattare la chiave pubblica nel formato JWKS
    jwks = {
        "keys": [key.as_dict()]
    }
    return jsonify(jwks)


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    print("route /oauth/authorize")
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        print("not user")
        return redirect(url_for('home.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            print("OAuth2Error", error)
            return error.error
            print("return authorize.html")
        print("User is logged in, go to grant page", user, grant)
        return render_template('authorize.html', user=user, grant=grant)

    if not user and 'username' in request.form:
        username = request.form.get('username')
        print("received user", username)
        user = User.query.filter_by(username=username).first()
    else:
        print("logged in as:", user)

    if request.form['confirm']:
        print("confirm ok")
        grant_user = user
    else:
        print("no confirm")
        grant_user = None

    print("grant user...", grant_user)
    res = authorization.create_authorization_response(grant_user=grant_user)
    print("grant user done", res)
    return res


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    print("route /oauth/token")
    res = authorization.create_token_response()
    print("result", res)
    return res


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    print("route /oauth/revoke")
    res = authorization.create_endpoint_response('revocation')
    print("result", res)
    return res


@bp.route('/oauth/me')
@require_oauth('profile')
def api_me():
    print("route /api/me")
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
