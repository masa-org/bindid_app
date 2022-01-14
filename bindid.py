#" For web application
from flask import Flask, request, render_template, abort

# Utilities
from datetime import datetime
import configparser
import json
import logging
import logging.config

# For calling external REST API
import requests, pprint, urllib

# For decoding JWT
import jwt

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
g_bind_id_host = ""
        
logger = logging.getLogger('app')

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
    url = g_bind_id_host + "/token"
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
    r = requests.post( url, headers=header, data=payload )

    # Convert response to JSON
    user_token_json = r.json()
    logger.warn( "User Token:\n" + json.dumps( user_token_json, indent=2 ))

    # Retrieve the signing key to validate the ID token 
    url = g_bind_id_host + "/jwks"
    r = requests.get( url )
    sign_key_json = r.json()
    logger.warn( "Sign key:\n" + json.dumps( sign_key_json, indent=2 ))

    # Decode ID Token

    return render_template('auth_success.html', 
            user_token=json.dumps(user_token_json, indent=2), 
            sign_key=json.dumps(sign_key_json, indent=2) )

@app.route("/auth-failure")
def auth_failure():
    # Just show error page
    return render_template('auth_failure.html')

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
        g_bind_id_host  = conf['BINDID']['BINDID_HOST']

        context = ( conf['APP']['TLS_CERT'], conf['APP']['TLS_PRIVATE_KEY'] )
        app.run(host='0.0.0.0', port=int(conf['APP']['PORT']), ssl_context=context)

    except Exception as e:
        logging.error("There was an error starting the server: {}".format(e))

