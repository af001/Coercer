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

    allowed_responses = [TestResult.HTTP_AUTH_RECEIVED.name, TestResult.SMB_AUTH_RECEIVED.name]

    def __init__(self, options, verbose=False):
        super(Reporter, self).__init__()
        self.options = options
        self.verbose = verbose

        if self.options.export_json is not None:
            self.test_results = self.load_json()
            if self.test_results is None:
                self.test_results = []
        else:
            self.test_results = []

    def report_test_result(self, target, uuid, version, named_pipe, msprotocol_rpc_instance, result, exploit_path):

        # Create new dict entry
        new_result = {
            "target": target,
            "access": {"type": "npcan_np", "namedpipe": named_pipe, "uuid": uuid, "version": version},
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "test_result": result.name,
            "exploit_path": exploit_path

        }

        if self.options.verbose:
            print(new_result)

        if str(result.name) in Reporter.allowed_responses:
            self.test_results.append(new_result)

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
