from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, render_template
)

from flask import jsonify as json_response

from webauthn_rp.backends import CredentialsBackend
from webauthn_rp.builders import *
from webauthn_rp.converters import cose_key, jsonify
from webauthn_rp.errors import WebAuthnRPError
from webauthn_rp.parsers import parse_cose_key, parse_public_key_credential
from webauthn_rp.registrars import *
from webauthn_rp.types import (
    AttestationObject, AttestationType, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorData,
    COSEAlgorithmIdentifier, PublicKeyCredential,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, TrustedPath)

import secrets
import datetime as dt

from database import *

bp = Blueprint('auth', __name__, url_prefix='/auth')

class RegistrarImpl(CredentialsRegistrar):
    def register_credential_attestation(self, credential, att, att_type, user, rp, trusted_path = None):
        if att.auth_data is None: raise ValueError
        if att.auth_data.attested_credential_data is None: raise ValueError
        cpk = att.auth_data.attested_credential_data.credential_public_key

        user = User.get_or_none(id=user.id)
        if user is None: return 'No user found'

        Credential.create(raw_id=credential.raw_id, signature_count=None, public_key=cose_key(cpk), user=user)

    def register_credential_assertion(self, credential, authenticator_data, user, rp):
        credential = Credential.get(raw_id=credential.raw_id)
        credential.signature_count = authenticator_data.sign_count

    def get_credential_data(self, credential_id: bytes):
        credential = Credential.get_or_none(raw=credential_id)
        if credential is None:
            return None

        return CredentialData(
            parse_cose_key(credential.public_key),
            credential.signature_count,
            PublicKeyCredentialUserEntity(
                name=credential.user.username,
                id=credential.user.user_handle,
                display_name=credential.user.username))


##### Webauthn-RP configuration

APP_ORIGIN = 'http://localhost:5000'
APP_TIMEOUT = dt.timedelta(seconds=60)
APP_RELYING_PARTY = PublicKeyCredentialRpEntity(name='localhost',
                                                id='localhost')

APP_CCO_BUILDER = CredentialCreationOptionsBuilder(
    rp=APP_RELYING_PARTY,
    pub_key_cred_params=[
        PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,
                                      alg=COSEAlgorithmIdentifier.Value.ES256)
    ],
    timeout=APP_TIMEOUT,
)

APP_CRO_BUILDER = CredentialRequestOptionsBuilder(
    rp_id=APP_RELYING_PARTY.id,
    timeout=APP_TIMEOUT,
)

APP_CREDENTIALS_BACKEND = CredentialsBackend(RegistrarImpl())

###### URL handlers

@bp.route('/')
def auth_index():
    return render_template('registration.html')

@bp.route('/registration/request/', methods=['POST'])
def registration_request():
    username = request.form['username']

    if User.select(pw.fn.count(1)).scalar():
        return ("User already registered! Delete it before registering again.", 400)

    user = User.create(username=request.form['username'],
            user_handle=secrets.token_bytes(64)
            )

    challenge = Challenge.create(request=secrets.token_bytes(64), user=user)

    options = APP_CCO_BUILDER.build(
        user=PublicKeyCredentialUserEntity(name=username,
                                           id=user.user_handle,
                                           display_name=username),
        challenge=challenge.request,
    )

    print(options, type(options))

    options_json = jsonify(options)
    response_json = {
        'challengeID': challenge.id,
        'creationOptions': options_json,
    }

    return json_response(response_json)


@bp.route('/registration/response/', methods=['POST'])
def registration_response():
    if User.select(pw.fn.count(1)).join(Credential).scalar():
        return ("User already registered! Delete it before registering again.", 400)
    
    try:
        challengeID = request.form['challengeID']
        credential = parse_public_key_credential(
            json.loads(request.form['credential']))
        username = request.form['username']
    except Exception:
        return ('Could not parse input data', 400)

    if type(credential.response) is not AuthenticatorAttestationResponse:
        return ('Invalid response type', 400)

    challenge = Challenge.get_or_none(raw_id=challengeID)
    if not challenge:
        return ('Could not find challenge matching given id', 400)

    user = User.get_or_none(username=username)
    if not user:
        return ('Invalid username', 400)

    if dt.datetime.now() - challenge_model.dt > APP_TIMEOUT:
        return ('Timeout', 408)

    user_entity = PublicKeyCredentialUserEntity(name=username,
                                                id=user.user_handle,
                                                display_name=username)

    try:
        APP_CREDENTIALS_BACKEND.handle_credential_attestation(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge_model.request,
            expected_origin=APP_ORIGIN)
    except WebAuthnRPError:
        return ('Could not handle credential attestation', 400)

    return ('Success', 200)


@bp.route('/authentication/request/', methods=['POST'])
def authentication_request():
    username = request.form['username']

    user = User.get_or_none(username=username)
    if user is None:
        return ('User not registered', 400)

    credentials = list(Credential.select().where(Credential.user == user))
    if not credentials:
        return ('User without credential', 400)

    challenge = Challenge.create(request=secrets.token_bytes(64), user=user)

    options = APP_CRO_BUILDER.build(
        challenge=challenge.request,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=cred.id,
                type=PublicKeyCredentialType.PUBLIC_KEY,
            ) for cred in credentials
        ])

    options_json = jsonify(options)
    response_json = {
        'challengeID': challenge.id,
        'requestOptions': options_json,
    }

    return json_response(response_json)


@bp.route('/authentication/response/', methods=['POST'])
def authentication_response():
    try:
        challengeID = request.form['challengeID']
        credential = parse_public_key_credential(
            json.loads(request.form['credential']))
        username = request.form['username']
    except Exception:
        return ('Could not parse input data', 400)

    if type(credential.response) is not AuthenticatorAssertionResponse:
        return ('Invalid response type', 400)

    challenge = Challenge.get_or_none(raw_id=challengeID)
    if not challenge:
        return ('Could not find challenge matching given id', 400)

    user = User.get_or_none(username=username)
    if not user:
        return ('Invalid username', 400)
    
    if dt.datetime.now() - challenge_model.dt > APP_TIMEOUT:
        return ('Timeout', 408)

    user_entity = PublicKeyCredentialUserEntity(name=username,
                                                id=user.user_handle,
                                                display_name=username)

    try:
        APP_CREDENTIALS_BACKEND.handle_credential_assertion(
            credential=credential,
            user=user_entity,
            rp=APP_RELYING_PARTY,
            expected_challenge=challenge.request,
            expected_origin=APP_ORIGIN)
    except WebAuthnRPError:
        return ('Could not handle credential assertion', 400)

    return ('Success', 200)

