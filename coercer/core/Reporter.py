#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import os
import json

from coercer.structures.TestResult import TestResult


class Reporter(object):
    """Reporter Class"""

    allowed_response = [TestResult.HTTP_AUTH_RECEIVED, TestResult.SMB_AUTH_RECEIVED]

    def __init__(self, options, verbose=False):
        super(Reporter, self).__init__()
        self.options = options
        self.verbose = verbose

        if self.options.export_json is not None:
            self.test_results = self.load_json()
            print('reloading')
            if self.test_results is None:
                self.test_results = {}
        else:
            self.test_results = {}

    def report_test_result(self, target, uuid, version, named_pipe, msprotocol_rpc_instance, result, exploit_path):
        function_name = msprotocol_rpc_instance.function["name"]

        if uuid not in self.test_results.keys():
            self.test_results[uuid] = {}
        if version not in self.test_results[uuid].keys():
            self.test_results[uuid][version] = {}
        if function_name not in self.test_results[uuid][version].keys():
            self.test_results[uuid][version][function_name] = {}
        if named_pipe not in self.test_results[uuid][version][function_name].keys():
            self.test_results[uuid][version][function_name][named_pipe] = []

        # Create new dict entry
        new_result = {
            "target": target,
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "test_result": result.name,
            "named_pipe": exploit_path
        }

        # Save result to database
        if str(result.name) in Reporter.allowed_response:
            self.test_results[target][uuid][version][function_name][named_pipe].append(new_result)

        if self.options.export_json is not None:
            self.export_json()

        if self.options.verbose:
            print(new_result)

    def load_json(self):
        base_path = os.path.dirname(self.options.export_json)
        filename = os.path.basename(self.options.export_json)
        path_to_file = base_path + os.path.sep + filename
        if os.path.isfile(path_to_file):
            with open(path_to_file, 'r') as f:
                return json.load(f)
        else:
            return None

    def export_json(self):
        base_path = os.path.dirname(self.options.export_json)
        filename = os.path.basename(self.options.export_json)
        if base_path not in [".", ""]:
            if not os.path.exists(base_path):
                os.makedirs(base_path)
            path_to_file = base_path + os.path.sep + filename
        else:
            path_to_file = filename
        # export
        with open(path_to_file, "w") as f:
            f.write(json.dumps(self.test_results, indent=4))
