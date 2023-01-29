#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Listener.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import socket
import time
from coercer.structures.TestResult import TestResult


class Listener(object):
    """Class Listener"""

    def __init__(self, options, timeout=None):
        super(Listener, self).__init__()

        self.smb_port = options.smb_port if options.smb_port else 445
        self.http_port = options.http_port if options.http_port else 80
        self.timeout = timeout if timeout is not None else 2
        self.listen_ip = options.listener_ip if options.listener_ip is not None else '0.0.0.0'
        self.auth_type = options.auth_type if options.auth_type is not None else 'smb'

    def start_server(self, control_structure):
        if self.auth_type == 'smb':
            port = self.smb_port
        else:
            port = self.http_port

        start_time = int(time.time())
        stop_time = start_time + self.timeout
        while (int(time.time()) < stop_time) and control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)

            try:
                s.bind((self.listen_ip, port))
            except Exception as e:
                print(f'Error: {e}')
                pass
            else:
                s.listen(5)
                conn, address = s.accept()
                data = conn.recv(2048)

                if data.startswith(b'\x00\x00\x00') and b'SMB' in data:
                    control_structure["result"] = TestResult.SMB_AUTH_RECEIVED
                elif b'HTTP' in data:
                    control_structure["result"] = TestResult.HTTP_AUTH_RECEIVED
                else:
                    pass
            finally:
                s.close()
