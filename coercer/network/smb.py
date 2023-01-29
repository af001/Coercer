#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : smb.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022


import sys
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin
from impacket.smbconnection import SMBConnection, SessionError


def try_login(credentials, target, port=445, verbose=False):
    """Try login"""
    # Checking credentials if any
    if not credentials.is_anonymous():
        try:
            smb_client = SMBConnection(
                remoteName=target,
                remoteHost=target,
                sess_port=int(port)
            )
            smb_client.login(
                user=credentials.username,
                password=credentials.password,
                domain=credentials.domain,
                lmhash=credentials.lmhash,
                nthash=credentials.nthash
            )
        except Exception as e:
            if verbose:
                print("[!] Could not login as '%s' with these credentials on '%s'." % (credentials.username, target))
                print("  | Error: %s" % str(e))
            return False
        else:
            smb_client.close()
            return True
    else:
        return True


def can_connect(target, pipe, credentials, uuid, version):

    ncan_target = fr'ncacn_np:{target}[{pipe}]'
    _rpctransport = transport.DCERPCTransportFactory(ncan_target)

    if hasattr(_rpctransport, 'set_credentials'):
        _rpctransport.set_credentials(
            username=credentials.username,
            password=credentials.password,
            domain=credentials.domain,
            lmhash=credentials.lmhash,
            nthash=credentials.nthash
        )

    if credentials.doKerberos:
        _rpctransport.set_kerberos(credentials.doKerberos, kdcHost=credentials.kdcHost)

    dce = _rpctransport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    # Try to connect
    try:
        dce.connect()
    except Exception:
        return False

    # Try to bind
    try:
        dce.bind(uuidtup_to_bin((uuid, version)))
    except Exception:
        return False
    else:
        dce.disconnect()
        return True
