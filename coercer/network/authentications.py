#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : authentications.py
# Author             : Podalirius (@podalirius_)
# Date created       : 21 Sep 2022

import time
from coercer.structures.TestResult import TestResult
from concurrent.futures import ThreadPoolExecutor
from coercer.network.Listener import Listener


def trigger_and_catch_authentication(options, dcerpc_session, target, method_trigger_function, listener_type,
                                     listen_ip=None):

    listener_type = listener_type.lower()
    if listener_type not in ["smb", "http"]:
        if options.verbose:
            print(f"[!] Unknown listener type '{listener_type}'")
        return False
    else:
        control_structure = {"result": TestResult.NO_AUTH_RECEIVED}
        # Waits for all the threads to be completed

        with ThreadPoolExecutor(max_workers=3) as tp:
            listener_instance = Listener(options=options, listen_ip=listen_ip)

            if listener_type == "smb":
                tp.submit(listener_instance.start_server, control_structure)

            elif listener_type == "http":
                tp.submit(listener_instance.start_server, control_structure)

            time.sleep(0.25)
            result_trigger = tp.submit(method_trigger_function, dcerpc_session, target)

        return process_test_results(control_structure, result_trigger)


def trigger_authentication(dcerpc_session, target, method_trigger_function):
    control_structure = {"result": TestResult.NO_AUTH_RECEIVED}
    result_trigger = method_trigger_function(dcerpc_session, target)
    return process_test_results(control_structure, result_trigger)


def process_test_results(control_structure, result_trigger):

    if control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
        if "rpc_x_bad_stub_data" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_X_BAD_STUB_DATA

        elif "nca_s_unk_if" in str(result_trigger):
            control_structure["result"] = TestResult.NCA_S_UNK_IF

        elif "rpc_s_access_denied" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_ACCESS_DENIED

        elif "ERROR_BAD_NETPATH" in str(result_trigger):
            control_structure["result"] = TestResult.ERROR_BAD_NETPATH

        elif "ERROR_INVALID_NAME" in str(result_trigger):
            control_structure["result"] = TestResult.ERROR_INVALID_NAME

        elif "STATUS_PIPE_DISCONNECTED" in str(result_trigger):
            control_structure["result"] = TestResult.SMB_STATUS_PIPE_DISCONNECTED

        elif "RPC_S_INVALID_BINDING" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_INVALID_BINDING

        elif "RPC_S_INVALID_NET_ADDR" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_INVALID_NET_ADDR

    return control_structure["result"]
