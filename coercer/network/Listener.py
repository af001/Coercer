#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Listener.py
# Author             : Podalirius (@podalirius_)

import socket
import time
from binascii import hexlify
from socket import socket, AF_PACKET, SOCK_RAW, IP_HDRINCL, IPPROTO_IP, IPPROTO_RAW
from coercer.structures.TestResult import TestResult


class Listener(object):
    """Class Listener"""

    def __init__(self, options, timeout=None):
        super(Listener, self).__init__()

        self.smb_port = options.smb_port if options.smb_port else 445
        self.http_port = options.http_port if options.http_port else 80
        self.timeout = timeout if timeout is not None else 1
        self.listen_ip = options.listener_ip if options.listener_ip is not None else '0.0.0.0'
        self.auth_type = options.auth_type if options.auth_type is not None else 'smb'

    def start_server(self, control_structure):

        start_time = int(time.time())
        stop_time = start_time + self.timeout
        while (int(time.time()) < stop_time) and control_structure["result"] == TestResult.NO_AUTH_RECEIVED:

            # Create listening socket with filters
            s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

            try:
                s.bind((self.listen_ip, 0))
            except Exception as e:
                print(f'exception: {e}')
                pass
            else:
                data, addr = s.recvfrom(1024)
                print('got data from', addr, ':', hexlify(data))

                if data.startswith(b'\x00\x00\x00') and b'SMB' in data:
                    control_structure["result"] = TestResult.SMB_AUTH_RECEIVED
                elif b'HTTP' in data:
                    control_structure["result"] = TestResult.HTTP_AUTH_RECEIVED
                else:
                    pass
            finally:
                s.close()
