#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_antivirus_profile
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    antivirus_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            analytics-bl-filetype:
                type: str
                description: no description
            analytics-db:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            analytics-max-upload:
                type: int
                description: no description
            analytics-wl-filetype:
                type: str
                description: no description
            av-block-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            av-virus-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: no description
            extended-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ftgd-analytics:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'suspicious'
                    - 'everything'
            inspection-mode:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow-based'
            mobile-malware-db:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: no description
            replacemsg-group:
                type: str
                description: no description
            scan-mode:
                type: str
                description: no description
                choices:
                    - 'quick'
                    - 'full'
                    - 'legacy'
                    - 'default'
            feature-set:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow'
            cifs:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - quarantine
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            content-disarm:
                description: no description
                type: dict
                required: false
                suboptions:
                    cover-page:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    detect-only:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    error-action:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'log-only'
                            - 'ignore'
                    office-action:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    office-dde:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    office-embed:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    office-hylink:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    office-linked:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    office-macro:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    original-file-destination:
                        type: str
                        description: no description
                        choices:
                            - 'fortisandbox'
                            - 'quarantine'
                            - 'discard'
                    pdf-act-form:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-gotor:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-java:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-launch:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-movie:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-act-sound:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-embedfile:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-hyperlink:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf-javacode:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            http:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    content-disarm:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                         - strict-file
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            imap:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    content-disarm:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            mapi:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            nac-quar:
                description: no description
                type: dict
                required: false
                suboptions:
                    expiry:
                        type: str
                        description: no description
                    infected:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'quar-src-ip'
                            - 'quar-interface'
                    log:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            nntp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            outbreak-prevention:
                description: no description
                type: dict
                required: false
                suboptions:
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd-service:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    content-disarm:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            smtp:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    content-disarm:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        description: no description
                        type: list
                        choices:
                         - scan
                         - file-filter
                         - quarantine
                         - avquery
                         - avmonitor
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    archive-block:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    archive-log:
                        description: no description
                        type: list
                        choices:
                         - encrypted
                         - corrupted
                         - multipart
                         - nested
                         - mailbomb
                         - unhandled
                         - partiallycorrupted
                         - fileslimit
                         - timeout
                    emulator:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - avmonitor
                         - quarantine
                         - scan
                    outbreak-prevention:
                        type: str
                        description: no description
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external-blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
            analytics-accept-filetype:
                type: str
                description: no description
            analytics-ignore-filetype:
                type: str
                description: no description
            ems-threat-feed:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            external-blocklist:
                type: str
                description: no description
            external-blocklist-archive-scan:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            external-blocklist-enable-all:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            outbreak-prevention-archive-scan:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            fortindr-error-action:
                type: str
                description: no description
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortindr-timeout-action:
                type: str
                description: no description
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox-error-action:
                type: str
                description: no description
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox-max-upload:
                type: int
                description: no description
            fortisandbox-mode:
                type: str
                description: no description
                choices:
                    - 'inline'
                    - 'analytics-suspicious'
                    - 'analytics-everything'
            fortisandbox-timeout-action:
                type: str
                description: no description
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure AntiVirus profiles.
      fmgr_antivirus_profile:
         adom: ansible
         state: present
         antivirus_profile:
            analytics-db: disable
            analytics-max-upload: 20
            av-block-log: disable
            av-virus-log: disable
            comment: 'test comment'
            extended-log: disable
            ftgd-analytics: disable
            inspection-mode: proxy
            mobile-malware-db: disable
            name: 'antivirus-profile'
            scan-mode: quick
 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the antivirus profiles
      fmgr_fact:
        facts:
            selector: 'antivirus_profile'
            params:
                adom: 'ansible'
                profile: 'your_value'
'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/antivirus/profile',
        '/pm/config/global/obj/antivirus/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
        '/pm/config/global/obj/antivirus/profile/{profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'antivirus_profile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'analytics-bl-filetype': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'analytics-db': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'analytics-max-upload': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'analytics-wl-filetype': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'av-block-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av-virus-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'extended-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ftgd-analytics': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'suspicious',
                        'everything'
                    ],
                    'type': 'str'
                },
                'inspection-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'proxy',
                        'flow-based'
                    ],
                    'type': 'str'
                },
                'mobile-malware-db': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'scan-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'quick',
                        'full',
                        'legacy',
                        'default'
                    ],
                    'type': 'str'
                },
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'cifs': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'quarantine',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'content-disarm': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cover-page': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'detect-only': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'error-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'log-only',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'office-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-dde': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-embed': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-hylink': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-linked': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'office-macro': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'original-file-destination': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'fortisandbox',
                                'quarantine',
                                'discard'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-form': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-gotor': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-java': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-launch': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-movie': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-act-sound': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-embedfile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-hyperlink': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdf-javacode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ftp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'http': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor',
                                'strict-file'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'imap': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mapi': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'nac-quar': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'expiry': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'infected': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'none',
                                'quar-src-ip',
                                'quar-interface'
                            ],
                            'type': 'str'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'nntp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'outbreak-prevention': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ftgd-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'pop3': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'smtp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'content-disarm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'executables': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'virus'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'scan',
                                'file-filter',
                                'quarantine',
                                'avquery',
                                'avmonitor'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ssh': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'archive-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'encrypted',
                                'corrupted',
                                'multipart',
                                'nested',
                                'mailbomb',
                                'unhandled',
                                'partiallycorrupted',
                                'fileslimit',
                                'timeout'
                            ]
                        },
                        'emulator': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'avmonitor',
                                'quarantine',
                                'scan'
                            ]
                        },
                        'outbreak-prevention': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disabled',
                                'files',
                                'full-archive',
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'av-scan': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'external-blocklist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'monitor',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortindr': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'block',
                                'monitor'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'analytics-accept-filetype': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'analytics-ignore-filetype': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ems-threat-feed': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'external-blocklist': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'external-blocklist-archive-scan': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'external-blocklist-enable-all': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'outbreak-prevention-archive-scan': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fortindr-error-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortindr-timeout-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortisandbox-error-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'fortisandbox-max-upload': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'fortisandbox-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'inline',
                        'analytics-suspicious',
                        'analytics-everything'
                    ],
                    'type': 'str'
                },
                'fortisandbox-timeout-action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'log-only',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
