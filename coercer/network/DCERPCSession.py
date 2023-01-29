#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DCERPCSession.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class DCERPCSession(object):
    """DCERPCSession Class"""

    def __init__(self, credentials, verbose=False, rpc_transport=None, session=None, target=None):
        super(DCERPCSession, self).__init__()
        self._verbose = verbose
        self.credentials = credentials
        self._rpc_transport = rpc_transport
        self.session = session
        self.target = target

    def connect_ncacn_np(self, target, pipe, target_ip=None, debug=False):

        self.target = target
        ncan_target = fr'ncacn_np:{target}[{pipe}]'
        self._rpc_transport = transport.DCERPCTransportFactory(ncan_target)

        if hasattr(self._rpc_transport, 'set_credentials'):
            self._rpc_transport.set_credentials(
                username=self.credentials.username,
                password=self.credentials.password,
                domain=self.credentials.domain,
                lmhash=self.credentials.lmhash,
                nthash=self.credentials.nthash
            )

        if self.credentials.doKerberos:
            self._rpc_transport.set_kerberos(self.credentials.doKerberos, kdcHost=self.credentials.kdcHost)
        if target_ip is not None:
            self._rpc_transport.setRemoteHost(target_ip)

        self.session = self._rpc_transport.get_dce_rpc()
        self.session.set_auth_type(RPC_C_AUTHN_WINNT)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        # Connecting to named pipe
        if debug:
            print(f" > Connecting to {ncan_target} ... ")
            sys.stdout.flush()

        try:
            self.session.connect()
        except Exception as e:
            if debug:
                print(f'Error: {e}')
            return None
        else:
            if debug:
                print('Success')
        return self.session

    def bind(self, interface_uuid, interface_version, debug=False):
        """Binding to interface"""
        if debug:
            print(f" > Binding to interface <uuid='{interface_uuid} version='{interface_version}'> ... ")
            sys.stdout.flush()
        try:
            self.session.bind(uuidtup_to_bin((interface_uuid, interface_version)))
        except Exception as e:
            if debug:
                print(f" > Something went wrong, check error status => {e}")
            return False
        else:
            if debug:
                print("Success")
        return True
