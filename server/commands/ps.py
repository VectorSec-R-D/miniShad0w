#
# Enumerate the running processes
#

import sys
import json
import base64

__description__ = "Get the running processes"
__author__ = "@_batsec_"

EXEC_ID    = 0x4000
OPCODE_PID = 0x8000

def ps_callback(shad0w, data):
    data = base64.b64decode(data)
    print(data)
    #sys.stdout.write(data.decode("utf-8"))

    return ""

def main(shad0w, args):

    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.error("ERROR: No active beacon")
        return

    # make the json
    #data = {"op" : OPCODE_PID, "args": "null"}
    #data = json.dumps(data)

    # set a task for the current beacon to do
    shad0w.beacons[shad0w.current_beacon]["callback"] = ps_callback
    shad0w.beacons[shad0w.current_beacon]["task"] = "STL gps"