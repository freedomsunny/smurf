# encoding=utf-8
# Auth huangyingjun
# date 05/09/2015


import telnetlib
import logging
import threading
import re

logger = logging.getLogger(__name__)
mutex = threading.Lock()


class SwitchConfig(object):
    def __init__(self, ip=None, port=23, username='admin', password='xiangcloud!@#', timeout=5):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout

    def send_cmd(self, cmds, write=True):
        tn = telnetlib.Telnet(host=self.ip, port=self.port, timeout=self.timeout)
        full_cmd = [['Username:', self.username], ['Password:', self.password], ['>', 'system-view']]
        for s in cmds:
            full_cmd.append([']', s])
            if "clear configuration interface" in s:
                full_cmd.append(['[Y/N]', 'Y'])

        if write:
            write_cmds = [[']', 'return'], ['>', 'save'], ['[Y/N]', 'Y']]
            [full_cmd.append(s) for s in write_cmds]

        for finish, cmd in full_cmd:
            try:
                logger.info("runing command : %s" % cmd)
                tn.read_until(str(finish))
                tn.write(str(cmd) + '\n')
                ret = re.search(r"Error", tn.read_some())
                if ret is not None:
                    logger.info("telnet send cmd error %s " % cmd)
            except Exception as e:
                logger.warn("Error send command : %s  error %s" % (cmd, str(e)))
        tn.close()

    def set_access(self, port, vlan):
        cmd = ["interface %s" % port,
               "port link-type access",
               "port default vlan %d" % vlan]

        self.send_cmd(cmd)

    def set_trunk(self, port, permit_vlan=None, permit_default_vlan=False):
        cmd = ["interface %s" % port,
               "port link-type trunk"]

        if not permit_vlan:
            cmd.append("port trunk allow-pass vlan 2 to 4094")
        else:
            cmd.append("port trunk allow-pass vlan %d" % permit_vlan)

        if not permit_default_vlan:
            cmd.append("undo port trunk allow-pass vlan 1")
        else:
            cmd.append("port trunk allow-pass vlan 1")

        self.send_cmd(cmd)

    def set_down(self, port):
        cmd = ["interface %s" % port, "shutdown"]

        self.send_cmd(cmd)

    def set_up(self, port):
        cmd = ["interface %s" % port, "undo shutdown"]

        self.send_cmd(cmd)

    def clean_config(self, port):
        cmd = ["clear configuration interface %s" % port,
               "interface %s" % port,
               "undo shutdown"]

        self.send_cmd(cmd)

if __name__ == '__main__':
    o = SwitchConfig(ip='172.16.66.251')
    o.send_cmd(['interface GigabitEthernet0/0/19', 'port link-type trunk'])
