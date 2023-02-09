#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Listener.py
# Author             : Podalirius (@podalirius_)

import socket
import time
from binascii import hexlify
from ctypes import create_string_buffer, addressof
from socket import socket, AF_PACKET, SOCK_RAW, SOL_SOCKET
from struct import pack, unpack
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
        self.interface = options.interface if options.interface is not None else None

    @staticmethod
    def bpf_jump(code, k, jt, jf):
        return pack(b'HBBI', code, jt, jf, k)

    def bpf_stmt(self, code, k):
        return self.bpf_jump(code, k, 0, 0)

    def start_server(self, control_structure):
        # Instruction classes
        BPF_LD = 0x00
        BPF_JMP = 0x05

        # ld/ldx fields
        BPF_H = 0x08
        BPF_ABS = 0x20

        # alu/jmp fields
        BPF_JEQ = 0x10
        BPF_K = 0x00

        # Ordering of the filters is backwards of what would be intuitive for
        # performance reasons: the check that is most likely to fail is first.
        filters_list = [
            self.bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 36),
            self.bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 80, 1, 0),
            self.bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 445, 0, 0),
        ]

        # Create filters struct and fprog struct to be used by SO_ATTACH_FILTER, as
        # defined in linux/filter.h.
        filters = b''.join(filters_list)
        b = create_string_buffer(filters)
        mem_addr_of_filters = addressof(b)
        fprog = pack('HL', len(filters_list), mem_addr_of_filters)

        # As defined in asm/socket.h
        SO_ATTACH_FILTER = 26

        start_time = int(time.time())
        stop_time = start_time + self.timeout
        while (int(time.time()) < stop_time) and control_structure["result"] == TestResult.NO_AUTH_RECEIVED:

            try:
                # Create listening socket with filters
                s = socket(AF_PACKET, SOCK_RAW, 0x0800)
                s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)
                s.bind((self.interface, 0x0800))
                s.settimeout(self.timeout)
            except Exception:
                pass
            else:
                data, addr = s.recvfrom(65565)
                print('got data from', addr, ':', hexlify(data))

                if data.startswith(b'\x00\x00\x00') and b'SMB' in data:
                    control_structure["result"] = TestResult.SMB_AUTH_RECEIVED
                elif b'HTTP' in data:
                    control_structure["result"] = TestResult.HTTP_AUTH_RECEIVED
                else:
                    pass
            finally:
                s.close()
