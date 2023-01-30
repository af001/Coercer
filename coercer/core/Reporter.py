#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import os
import json


class Reporter(object):
    """Reporter Class"""

    def __init__(self, options, verbose=False):
        super(Reporter, self).__init__()
        self.options = options
        self.verbose = verbose
        self.test_results = {}

    def report_test_result(self, target, uuid, version, named_pipe, msprotocol_rpc_instance, result, exploit_path):
        function_name = msprotocol_rpc_instance.function["name"]

        if target not in self.test_results.keys():
            self.test_results[target] = {}
        if uuid not in self.test_results.keys():
            self.test_results[target][uuid] = {}
        if version not in self.test_results[target][uuid].keys():
            self.test_results[target][uuid][version] = {}
        if function_name not in self.test_results[target][uuid][version].keys():
            self.test_results[target][uuid][version][function_name] = {}
        if named_pipe not in self.test_results[target][uuid][version][function_name].keys():
            self.test_results[target][uuid][version][function_name][named_pipe] = []

        # Save result to database
        self.test_results[target][uuid][version][function_name][named_pipe].append({
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "test_result": result.name,
            "named_pipe": exploit_path
        })

    def export_json(self, filename):
        base_path = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if base_path not in [".", ""]:
            if not os.path.exists(base_path):
                os.makedirs(base_path)
            path_to_file = base_path + os.path.sep + filename
        else:
            path_to_file = filename
        # export
        with open(path_to_file, "a") as f:
            f.write(json.dumps(self.test_results, indent=4))
