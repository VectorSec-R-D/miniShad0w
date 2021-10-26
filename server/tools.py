import os
import sys
import json
import time
import random
import hashlib
from pathlib import Path
from datetime import datetime

# list all command scripts in the commands dir, append to list of commands
def get_commands():
    commandList = []
    for _, _, f in os.walk("./commands"):
        for file in f:
            if file.endswith(".py") and "_" not in file:
                commandList.append(file.replace(".py",""))

    print(commandList)
    return commandList

def get_data_from_json(jdata):
    # get the data from data

    id     = ""
    data   = ""

    # if we get any errors, just return the above values
    # and this req will then be ignored
    try:
        id = jdata['id']
        if jdata['data']:
            data = jdata['data']
    except KeyError:
        pass

    # print("reting: ", (id, opcode, data))
    return id, data