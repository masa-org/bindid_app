# For web application
from flask import Flask, session, request, render_template, abort

# Utilities
from datetime import datetime, timedelta
import json, configparser, logging
import logging.config

# For calling external REST API
import requests, pprint, urllib

# For decoding JWT
import jwt

# For computing hmac sha256
import hashlib, hmac, base64, time

log_level = {
    'CRITICAL': 50,
    'ERROR': 40,
    'WARN': 30,
    'INFO': 20,
    'DEBUG': 10
}

# Global setting
g_client_id = ""
g_client_secret = ""
g_redirect_uri = ""
g_bindid_signin_host = ""
g_bindid_api_host = ""
        
logger = logging.getLogger('app')

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = 'verysensitivevalue'
app.config.from_object(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)

def read_config():
  conf = configparser.ConfigParser()
  with open('config.ini') as f:
    conf.read_file(f)
  return conf

@app.route("/", methods=['GET'])
def index():
    # Step2: Configure SDK in Login Page
    # Step3: Add Login button
    return render_template('index.html', client_id=g_client_id, redirect_uri=g_redirect_uri)

@app.route("/callback", methods=['GET'])
def callback():
    # Step4: Create Redirect page
    return render_template('callback.html', client_id=g_client_id)

@app.route("/auth-success")
def auth_success():
    # Step5: Get User Token
    # Step6: Handle User Token

    # Get auth_code from callback URL
    auth_code = request.args.get('code')
    logger.warn( "auth_code: " + auth_code )

    # Create POST API payload
    url = g_bindid_signin_host + "/token"
    header = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = { 
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": g_redirect_uri,
        "client_id": g_client_id,
        "client_secret": g_client_secret
    }

    payload = urllib.parse.urlencode(payload)

    # Invoke POST API
    try:
        r = requests.post( url, headers=header, data=payload )
        r.raise_for_status()
    except Exception as e:
        logging.error("There was an error making POST call: {}".format(e))

    # Convert response to JSON
    user_token_json = r.json()
    logger.warn( "User Token:\n" + json.dumps( user_token_json, indent=2 ))

    # Obtain ID token
    id_token = user_token_json["id_token"]
    logger.warn( "ID Token:\n" + id_token )

    # Obtain access token
    access_token = user_token_json["access_token"]
    session["access_token"] = access_token
    logger.warn( "Access Token:\n" + access_token )

    # Retrieve the signing key to validate the ID token 
    url = g_bindid_signin_host + "/jwks"

    try:
        r = requests.get( url )
        r.raise_for_status()
    except Exception as e:
        logging.error("There was an error making GET call: {}".format(e))

    sign_key_json = r.json()
    logger.warn( "Sign key:\n" + json.dumps( sign_key_json, indent=2 ))

    # Obtain pub key for decode
    pub_keys = {}
    for jwk in sign_key_json['keys']:
        kid = jwk['kid']
        pub_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk( json.dumps(jwk))

    logger.warn( "pub_keys:\n" + str( pub_keys ) )

    kid = jwt.get_unverified_header( id_token )['kid']
    logger.warn( "kid:\n" + kid );

    key = pub_keys[kid]
    logger.warn( "key:\n" + str( key ) );

    # Decode ID Token
    try:
        options = {
            "verify_signature": False
        }
        id_token_decoded = jwt.decode( 
            id_token, 
            key=key, 
            algorithms=['RS256'], 
            audience=g_client_id,
            issuer=g_bindid_signin_host)
    except Exception as e:
        logging.error("There was an error decoding ID token: {}".format(e))

    logger.warn( "ID token decoded:\n" + json.dumps( id_token_decoded ) );

    if "bindid_alias" in id_token_decoded:  
        # User exist
        return render_template('auth_success.html',
            user_token=json.dumps(user_token_json, indent=2), 
            sign_key=json.dumps(sign_key_json, indent=2),
            id_token=json.dumps(id_token_decoded, indent=2))
    else:
        # User not exist, so render user registration page
        return render_template('register_new_user.html')

@app.route("/auth-failure")
def auth_failure():
    # Just show error page
    return render_template('auth_failure.html')

@app.route("/register_new_user", methods=['POST'])
def register_new_user():
    # Register new user
    if "access_token" in session:
        logger.warn("Access token in Session!")
    else:
        logger.warn("Access token Not in Session!")

    # Get alias
    alias = request.form.get('alias')
    logger.warn( "Alias: " + alias )

    # Compute Feedback auth value
    try:
        hmac_sha256 = hmac.new( bytes(g_client_secret, 'UTF-8'), bytes( session['access_token'], 'UTF-8'), hashlib.sha256 ).digest()
    except Exception as e:
        logging.error("There was an error in HMAC SHA256: {}".format(e))
    
    feedback_auth_value = base64.b64encode( hmac_sha256 )
    logger.warn( "Feedback auth value: " + str(feedback_auth_value) )

    # Invoke 'session-feedback' API
    url = g_bindid_api_host + "/session-feedback"
    headers = { 
        "Content-Type": "application/json",
        "Authorization": "BindIdBackend AccessToken " + session['access_token'] + "; " + feedback_auth_value.decode('utf-8')
    }

    payload = { 
        "subject_session_at": session['access_token'],
        "reports": [{
            "type": "authentication_performed",
            "alias": alias,
            "time": int(time.time())
        }]
    }

    logger.warn( "headers:\n" + json.dumps( headers ))
    logger.warn( "payload:\n" + json.dumps( payload ))

    # Invoke POST API
    try:
        r = requests.post( url, headers=headers, json=payload)
        r.raise_for_status()
    except Exception as e:
        logging.error("There was an error making POST call: {}".format(e))

    return render_template('auth_success.html')


if __name__ == '__main__':
    logger.warn('In main...')
    conf = read_config()

    logging.basicConfig(
        level = log_level[conf['DEFAULT']['LogLevel']],
        format = '%(asctime)s - %(levelname)8s - %(name)9s - %(funcName)15s - %(message)s'
    )
    
    try: 
        g_client_id     = conf['BINDID']['CLIENT_ID']
        g_client_secret = conf['BINDID']['CLIENT_SECRET']
        g_redirect_uri  = conf['BINDID']['REDIRECT_URI']
        g_bindid_signin_host  = conf['BINDID']['BINDID_SIGNIN_HOST']
        g_bindid_api_host  = conf['BINDID']['BINDID_API_HOST']

        context = ( conf['APP']['TLS_CERT'], conf['APP']['TLS_PRIVATE_KEY'] )
        app.run(host='0.0.0.0', port=int(conf['APP']['PORT']), ssl_context=context)

    except Exception as e:
        logging.error("There was an error starting the server: {}".format(e))

