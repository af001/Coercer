#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Credentials.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022

class Credentials(object):
    """Credential Class"""

    def __init__(self, username, password, domain, lmhash, nthash, doKerberos=False, kdcHost=None):
        super(Credentials, self).__init__()
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost

    def is_anonymous(self):
        """Returns True if anonymous authentication is used False otherwise"""
        return True if self.username is None or len(self.username) == 0 else False

