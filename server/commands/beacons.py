#
#   List beacons and info about them
#

from prettytable import PrettyTable

__description__ = "Interact with or display current beacons"
__author__ = "@_batsec_"

def _list_beacons(shad0w):
    # i have gcse english, i gonna use it
    if shad0w.beacon_count == 1:
        shad0w.debug.log(f"{shad0w.beacon_count} active beacon\n", log=True)
    else:
        shad0w.debug.log(f"{shad0w.beacon_count} active beacons\n", log=True)

    t = PrettyTable(['Number', 'Session', "Last Checkin"])

    for beacon in shad0w.beacons.keys():

        # stuff we will display

        # beacon number
        num        = shad0w.beacons[beacon]["num"]

        # get last check in time
        checkin    = shad0w.beacons[beacon]["last_checkin"]

        # stuff to format for name
        beacon_id   = beacon
        ip_addr    = shad0w.beacons[beacon]["ip_addr"]

        # format of name
        short_name = f"{beacon_id}@{ip_addr}"

        # show it in the: (num   -   name) format
        # shad0w.debug.log(f"{num}\t-\t{short_name}\t-\t{checkin}", log=True, pre=False)
        t.add_row([num, short_name, checkin])
    
    print(t)

    return

def _interact_beacon(shad0w, args):
    # get beacon number
    interact_with = args[2]

    # check its a number
    try:
        interact_with = int(interact_with)
    except ValueError:
        shad0w.debug.log(f"'{interact_with}' is an invaild beacon", log=True)
        return

    # match the beacon number to the id and then set the current id as that
    for beacon in shad0w.beacons.keys():
        if shad0w.beacons[beacon]["num"] == interact_with:
            shad0w.current_beacon = beacon
            return

    shad0w.current_beacon = None

def main(shad0w, args):
    # decide what we will do

    if len(args) == 1:
        # list the active beacons
        _list_beacons(shad0w)

    else:
        if args[1] == "-i":
            _interact_beacon(shad0w, args)