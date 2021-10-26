# 
# Get infomation about the current user
#

import json

__description__ = "Get infomation about the current user the beacon is running as"
__author__ = "@_batsec_"

def whoami_callback(shad0w, data):
    shad0w.debug.log(data, log=True, pre=False)
    return ""

def main(shad0w, args):

    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.error("ERROR: No active beacon")
        return

    shad0w.beacons[shad0w.current_beacon]["callback"] = whoami_callback
    shad0w.beacons[shad0w.current_beacon]["task"] = "STL who"