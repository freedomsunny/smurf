#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threading
import time
import logging
from socket import timeout


logger = logging.getLogger(__name__)


class consoleThread (threading.Thread):
    def __init__(self,ws,sock):
        threading.Thread.__init__(self)
        self.ws = ws
        self.sock = sock

    def run(self): 
        while not self.ws.closed:
            try:
                resp = self.sock.recv(1024)

                # closed sock recv() returns "" on console 'exit'
                if resp != "":
                    self.ws.send(resp)
                else:
                    logger.info('sock closed normally')
                    self.ws.close()
                    break
            except timeout:
                pass
            except Exception as e:
                logger.warn('exception sock close, %s', e)
                self.ws.close()
                break

        self.sock.close()
