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


def list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1, debug=False):
    """Function list_remote_pipes(target, credentials, share='IPC$', maxdepth=-1, debug=False)"""
    pipes = []
    try:
        smbClient = SMBConnection(target, target, sess_port=int(445))
        dialect = smbClient.getDialect()
        if credentials.doKerberos is True:
            smbClient.kerberosLogin(credentials.username, credentials.password, credentials.domain, credentials.lmhash, credentials.nthash, credentials.aesKey, credentials.dc_ip)
        else:
            smbClient.login(credentials.username, credentials.password, credentials.domain, credentials.lmhash, credentials.nthash)
        if smbClient.isGuestSession() > 0:
            if debug:
                print("[>] GUEST Session Granted")
        else:
            if debug:
                print("[>] USER Session Granted")
    except Exception as e:
        if debug:
            print(e)
        return pipes

    # Breadth-first search algorithm to recursively find .extension files
    searchdirs = [""]
    depth = 0
    while len(searchdirs) != 0 and ((depth <= maxdepth) or (maxdepth == -1)):
        depth += 1
        next_dirs = []
        for sdir in searchdirs:
            if debug:
                print("[>] Searching in %s " % sdir)
            try:
                for sharedfile in smbClient.listPath(share, sdir + "*", password=''):
                    if sharedfile.get_longname() not in [".", ".."]:
                        if sharedfile.is_directory():
                            if debug:
                                print("[>] Found directory %s/" % sharedfile.get_longname())
                            next_dirs.append(sdir + sharedfile.get_longname() + "/")
                        else:
                            if debug:
                                print("[>] Found file %s" % sharedfile.get_longname())
                            full_path = sdir + sharedfile.get_longname()
                            pipes.append(full_path)
            except SessionError as e:
                if debug:
                    print("[error] %s " % e)
        searchdirs = next_dirs
        if debug:
            print("[>] Next iteration with %d folders." % len(next_dirs))
    pipes = sorted(list(set(["\\PIPE\\" + f for f in pipes])), key=lambda x: x.lower())
    return pipes


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
