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
        self.test_results = []

    def report_test_result(self, target, uuid, version, named_pipe, msprotocol_rpc_instance, result, exploit_path):

        # Create new dict entry
        new_result = {
            "target": target,
            "access": {"npcan_np": {"namedpipe": named_pipe, "uuid": uuid, "version": version}},
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "test_result": result.name,
            "exploit_path": exploit_path
        }

        if self.options.verbose:
            print(new_result)

        if str(result.name) in Reporter.allowed_responses:
            self.test_results.append(new_result)

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
        with open(path_to_file, "w") as f:
            f.write(json.dumps(self.test_results, indent=4))
