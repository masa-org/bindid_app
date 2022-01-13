from flask import Flask, request, render_template, abort

from datetime import datetime
import configparser
import json
import logging
import logging.config

log_level = {
    'CRITICAL': 50,
    'ERROR': 40,
    'WARN': 30,
    'INFO': 20,
    'DEBUG': 10
}

# Global setting
g_client_id = ""
g_redirect_uri = ""
        
logger = logging.getLogger('app')

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

def read_config():
  conf = configparser.ConfigParser()
  with open('config.ini') as f:
    conf.read_file(f)
  return conf

@app.route("/")
def index():
    return render_template('index.html', client_id=g_client_id, redirect_uri=g_redirect_uri)

@app.route("/callback")
def handle_():
    return "<p>Hello, World!</p>"

if __name__ == '__main__':
    logger.warn('In main...')
    conf = read_config()

    logging.basicConfig(
        level = log_level[conf['DEFAULT']['LogLevel']],
        format = '%(asctime)s - %(levelname)8s - %(name)9s - %(funcName)15s - %(message)s'
    )
    
    try: 
        g_client_id = conf['BINDID']['CLIENT_ID']
        g_redirect_uri = conf['BINDID']['REDIRECT_URI']

        app.run(host='0.0.0.0', port=int(conf['APP']['PORT'] ))

    except Exception as e:
        logging.error("There was an error starting the server: {}".format(e))

