from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

ISSUER='https://api.dizme.org/'

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    def save_authorization_code(self, code, request):

        print(f"AuthorizationCodeGrant.save_authorization_code: {code}")

        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):

        print(f"AuthorizationCodeGrant.query_authorization_code: {code}")

        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):

        print(f"AuthorizationCodeGrant.delete_authorization_code: {authorization_code}")

        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):

        print(f"AuthorizationCodeGrant.authenticate_user: {authorization_code}")

        token = User.query.get(authorization_code.user_id)
        print(f"AuthorizationCodeGrant.token?: {token}")
        return token


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):

        print(f"PasswordGrant.authenticate_user: {username}: {password}")

        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            return user

class CustomPasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):

        print(f"CustomPasswordGrant.authenticate_user: {username}: {password}")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return user

    def create_access_token(self, token, client, user):

        print(f"CustomPasswordGrant.create_access_token: {token}")

        header = {'alg': 'RS256'}
        payload = {
            'iss': ISSUER,
            'sub': str(user.id),
            'aud': client.client_id,
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
        }
        jwt_token = jwt.JWT(header=header, claims=payload)
        jwt_token.make_signed_token(key)
        return jwt_token.serialize()

    def save_bearer_token(self, token, request):

        print(f"CustomPasswordGrant.save_bearer_token: {token}")

        client = request.client
        user = request.user
        access_token = self.create_access_token(token, client, user)
        token['access_token'] = access_token

        item = OAuth2Token(
            client_id=client.client_id,
            user_id=user.id,
            **token
        )
        db.session.add(item)
        db.session.commit()

        return token



class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):

        print(f"RefreshTokenGrant.authenticate_refresh_token: {refresh_token}")

        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):

        print(f"RefreshTokenGrant.authenticate_user: {credential}")

        token = User.query.get(credential.user_id)
        print(f"RefreshTokenGrant.token?: {token}")
        return token

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()

######### OIDC Connect

from authlib.oidc.core import UserInfo
from authlib.oidc.core import grants as oidc_grants

class OIDCAuthorizationCodeGrant(AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):

        print(f"OIDCAuthorizationCodeGrant.save_authorization_code: {code}")

        # openid request MAY have "nonce" parameter
        nonce = request.data.get('nonce')
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):

        print(f"OIDCAuthorizationCodeGrant.query_authorization_code: {code}")

        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

def read_private_key_file(path):
    with open(path, 'r') as f:
        return f.read()

def read_public_key_file(path):
    with open(path, 'r') as f:
        key = f.read()
    # Rimuovi le intestazioni e le interruzioni di riga
    #key = key.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
    return key

class OpenIDCode(oidc_grants.OpenIDCode):

    def exists_nonce(self, nonce, request):

        print(f"OpenIDCode.exists_nonce: {nonce}")

        exists = OAuth2AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self, grant):

        print(f"OpenIDCode.get_jwt_config: {grant}")

        from authlib.jose import JsonWebKey, jwt

        key_data = read_public_key_file('public_key.pem')
        tmp_key = JsonWebKey.import_key(key_data, {'kty': 'RSA', 'kid': 'TEMP_KEY'})   # just to compute the thumbprint

        private_key_data = read_private_key_file('private_key.pem')
        private_key = JsonWebKey.import_key(private_key_data, {'kty': 'RSA', 'kid': tmp_key.thumbprint()})

        return {
            'key': private_key,
            'alg': 'RS256',
            'iss': ISSUER,
            'exp': 36000
        }

    def zzz_process_token(self, grant, token):

        print(f"OpenIDCode.process_token: {grant} : {token}")

        token = super().process_token(self, grant, token)

        token['id_token']['kid'] = ''


        scope = token.get('scope')
        print(f"OpenIDCode.process_token scope: {scope}")
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            print(f"OpenIDCode.process_token: standard authorization code flow")
            return token

        request: OAuth2Request = grant.request
        authorization_code = request.authorization_code

        config = self.get_jwt_config(grant)
        config['aud'] = self.get_audiences(request)

        if authorization_code:
            config['nonce'] = authorization_code.get_nonce()
            config['auth_time'] = authorization_code.get_auth_time()

        user_info = self.generate_user_info(request.user, token['scope'])
        id_token = generate_id_token(token, user_info, **config)
        token['id_token'] = id_token
        return token

    def generate_user_info(self, user, scope):

        print(f"OpenIDCode.generate_user_info: {user} {type(user)}, scope: {scope}")

        user_info = UserInfo(sub=user.get_user_id(), name=user.get_user_username())
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info


def config_oauth(app):

    print(f"config_oauth")

    authorization.init_app(app)

    # support all grants
    authorization.register_grant(grants.ImplicitGrant)
    authorization.register_grant(grants.ClientCredentialsGrant)
    #authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    #authorization.register_grant(PasswordGrant)
    authorization.register_grant(CustomPasswordGrant)

    authorization.register_grant(RefreshTokenGrant)
    # OIDC Connect
    authorization.register_grant(OIDCAuthorizationCodeGrant, [CodeChallenge(required=True), OpenIDCode(require_nonce=True)])

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
