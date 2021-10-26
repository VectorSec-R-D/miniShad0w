import os
import signal
import datetime
import traceback
import threading

import input_handler, cmd

from prompt_toolkit import PromptSession
from pygments.lexers.shell import PowerShellLexer
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML, ANSI
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.shortcuts import prompt, CompleteStyle, PromptSession

class Console(object):

    def __init__(self, shad0w):

        super(Console, self).__init__()
        # cause its kinda useful
        self.shad0w        = shad0w

        # prompts, might add a way to customize this
        self.prompt               = "shad0w ≫ "
        self.active_prompt        = "shad0w(\033[1;31m%s@%s\033[0m) ≫ "

        # handle all given commands
        self.cmd_handler   = input_handler.Handler(self.shad0w)

    def set_autocompletes(self):
        self.autocomplete = WordCompleter(cmd.Shad0wLexer.commands, ignore_case=True)
    
    def beacon_toolbar(self):
        if self.shad0w.current_beacon:
            checkin_diff = self.shad0w.beacons[self.shad0w.current_beacon]["last_checkin_raw"]
            ping_diff = datetime.datetime.now() - checkin_diff
            last_ping = f'<style bg="black">{ping_diff.seconds + 1}s</style>'
            
            ip_addr = self.shad0w.beacons[self.shad0w.current_beacon]["ip_addr"]
            ip_addr = f'<style bg="black">{ip_addr}</style>'

            return HTML(f'BeaconId: {self.shad0w.current_beacon} | IPaddr: {ip_addr} | Ping: {last_ping}')
        else:
            return HTML(f'<b><style bg="ansired">No Active Beacon</style></b>')
    
    async def start(self):

        # default history file
        histfile = FileHistory('.shad0w_history')

        # do what prompts do
        self.set_autocompletes()
        try:
            with patch_stdout():
                self.prompt_session = PromptSession(bottom_toolbar=self.beacon_toolbar, history=histfile, lexer=PygmentsLexer(cmd.Shad0wLexer), style=cmd.Shad0wLexer.lex_style, auto_suggest=AutoSuggestFromHistory())
        except ValueError: pass
        while True:
            try:
                # display a prompt depending on wheather we got an active beacon or not
                if self.shad0w.current_beacon is None:
                    input = await self.prompt_session.prompt_async(ANSI(self.prompt), completer=self.autocomplete, complete_style=CompleteStyle.READLINE_LIKE)
                else:
                    # stuff to format for name
                    ip_addr     = self.shad0w.beacons[self.shad0w.current_beacon]["ip_addr"]
                    beacon_id   = self.shad0w.current_beacon                    

                    with patch_stdout():
                        input = await self.prompt_session.prompt_async(ANSI(self.active_prompt % (beacon_id, ip_addr)), completer=self.autocomplete, complete_style=CompleteStyle.READLINE_LIKE, refresh_interval=0.5)

                # handle the input we just recived
                try:
                    with patch_stdout():
                        await self.cmd_handler.do(input)
                except Exception as e:

                    # tell user about error
                    print("ERROR:", e)

                    # if in debug mode drop the full traceback
                    if self.shad0w.debugv:  traceback.print_exc()

                    pass
            except KeyboardInterrupt:
                break