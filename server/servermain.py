import os
import sys
import ssl
import socket
import asyncio
import argparse

from threading import Thread

import debug
import banner
import console
import http_server

class shad0wC2(object):
    def __init__(self, args):

        super(shad0wC2, self).__init__()

        #payloads store
        self.paylaods = {}

        # declare all the vitial variables to run.
        self.addr                    = (args['address'], args['port'])
        self.debugv                  = args['debug']
        self.sslkey                  = args['key']
        self.sslcrt                  = args['cert']
        
        # runtime variables
        self.beacons                 = {}
        self.beacon_count            = 0
        self.current_beacon          = None

        # get the debug/logging stuff ready
        self.debug                   = debug.Debug(self.debugv)

        # console class
        self.console                 = console.Console(self)
    
    def start(self):

        banner.Banner()
        # start the http server thread
        # self.debug.log("starting http server thread")
        thttp = Thread(target=http_server.run_serv, args=(self,))
        thttp.daemon = False
        thttp.start()

        # start the console
        asyncio.run(self.console.start())

if __name__ == '__main__':

    # sort the first cmd switch to decide weather we beacon or listen
    parser = argparse.ArgumentParser(prog='shad0w')
    subparsers = parser.add_subparsers(dest='mode', help='shad0w C2 functions')
    listen_parser = subparsers.add_parser('listen', help="Tell shad0w to listen for connections")
    update_parser = subparsers.add_parser('update', help="Update shad0w")

    listen_parser.add_argument("-a", "--address", required=False, default="0.0.0.0", help="Address shad0w will listen on (default will be 0.0.0.0)")
    listen_parser.add_argument("-p", "--port", required=False, default=443, help="Port the C2 will bind to (default is 443)")
    listen_parser.add_argument("-k", "--key", required=False, default="certs/key.pem", help="Private key for the HTTPS server")
    listen_parser.add_argument("-c", "--cert", required=False, default="certs/cert.pem", help="Certificate for the HTTPS server")
    listen_parser.add_argument("-d", "--debug", required=False, action='store_true', help="Start debug mode")

    # parse the args
    args = vars(parser.parse_args())

    # first check if we need to update
    if args["mode"] == "update":
        print("Updating...")
        os.system("git pull")

    # set the arguments for the listen
    if args["mode"] == "listen":
        shad0w = shad0wC2(args)
        asyncio.run(shad0w.start())
