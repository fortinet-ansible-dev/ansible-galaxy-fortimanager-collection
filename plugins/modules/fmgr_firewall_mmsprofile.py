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
module: fmgr_firewall_mmsprofile
short_description: Configure MMS profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
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
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    firewall_mmsprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            avnotificationtable:
                type: str
                description: 'AntiVirus notification table ID.'
            bwordtable:
                type: str
                description: 'MMS banned word table ID.'
            carrier-endpoint-prefix:
                type: str
                description: 'Enable/disable prefixing of end point values.'
                choices:
                    - 'disable'
                    - 'enable'
            carrier-endpoint-prefix-range-max:
                type: int
                description: 'Maximum length of end point value that can be prefixed (1 - 48).'
            carrier-endpoint-prefix-range-min:
                type: int
                description: 'Minimum end point length to be prefixed (1 - 48).'
            carrier-endpoint-prefix-string:
                type: str
                description: 'String with which to prefix End point values.'
            carrierendpointbwltable:
                type: str
                description: 'Carrier end point filter table ID.'
            comment:
                type: str
                description: 'Comment.'
            mm1:
                description: 'MM1 options.'
                type: list
                choices:
                 - avmonitor
                 - block
                 - oversize
                 - quarantine
                 - scan
                 - avquery
                 - bannedword
                 - no-content-summary
                 - archive-summary
                 - archive-full
                 - carrier-endpoint-bwl
                 - remove-blocked
                 - chunkedbypass
                 - clientcomfort
                 - servercomfort
                 - strict-file
                 - mms-checksum
            mm1-addr-hdr:
                type: str
                description: 'HTTP header field (for MM1) containing user address.'
            mm1-addr-source:
                type: str
                description: 'Source for MM1 user address.'
                choices:
                    - 'http-header'
                    - 'cookie'
            mm1-convert-hex:
                type: str
                description: 'Enable/disable converting user address from HEX string for MM1.'
                choices:
                    - 'disable'
                    - 'enable'
            mm1-outbreak-prevention:
                type: str
                description: 'Enable FortiGuard Virus Outbreak Prevention service.'
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm1-retr-dupe:
                type: str
                description: 'Enable/disable duplicate scanning of MM1 retr.'
                choices:
                    - 'disable'
                    - 'enable'
            mm1-retrieve-scan:
                type: str
                description: 'Enable/disable scanning on MM1 retrieve configuration messages.'
                choices:
                    - 'disable'
                    - 'enable'
            mm1comfortamount:
                type: int
                description: 'MM1 comfort amount (0 - 4294967295).'
            mm1comfortinterval:
                type: int
                description: 'MM1 comfort interval (0 - 4294967295).'
            mm1oversizelimit:
                type: int
                description: 'Maximum file size to scan (1 - 819200 kB).'
            mm3:
                description: 'MM3 options.'
                type: list
                choices:
                 - avmonitor
                 - block
                 - oversize
                 - quarantine
                 - scan
                 - avquery
                 - bannedword
                 - no-content-summary
                 - archive-summary
                 - archive-full
                 - carrier-endpoint-bwl
                 - remove-blocked
                 - fragmail
                 - splice
                 - mms-checksum
            mm3-outbreak-prevention:
                type: str
                description: 'Enable FortiGuard Virus Outbreak Prevention service.'
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm3oversizelimit:
                type: int
                description: 'Maximum file size to scan (1 - 819200 kB).'
            mm4:
                description: 'MM4 options.'
                type: list
                choices:
                 - avmonitor
                 - block
                 - oversize
                 - quarantine
                 - scan
                 - avquery
                 - bannedword
                 - no-content-summary
                 - archive-summary
                 - archive-full
                 - carrier-endpoint-bwl
                 - remove-blocked
                 - fragmail
                 - splice
                 - mms-checksum
            mm4-outbreak-prevention:
                type: str
                description: 'Enable FortiGuard Virus Outbreak Prevention service.'
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm4oversizelimit:
                type: int
                description: 'Maximum file size to scan (1 - 819200 kB).'
            mm7:
                description: 'MM7 options.'
                type: list
                choices:
                 - avmonitor
                 - block
                 - oversize
                 - quarantine
                 - scan
                 - avquery
                 - bannedword
                 - no-content-summary
                 - archive-summary
                 - archive-full
                 - carrier-endpoint-bwl
                 - remove-blocked
                 - chunkedbypass
                 - clientcomfort
                 - servercomfort
                 - strict-file
                 - mms-checksum
            mm7-addr-hdr:
                type: str
                description: 'HTTP header field (for MM7) containing user address.'
            mm7-addr-source:
                type: str
                description: 'Source for MM7 user address.'
                choices:
                    - 'http-header'
                    - 'cookie'
            mm7-convert-hex:
                type: str
                description: 'Enable/disable conversion of user address from HEX string for MM7.'
                choices:
                    - 'disable'
                    - 'enable'
            mm7-outbreak-prevention:
                type: str
                description: 'Enable FortiGuard Virus Outbreak Prevention service.'
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm7comfortamount:
                type: int
                description: 'MM7 comfort amount (0 - 4294967295).'
            mm7comfortinterval:
                type: int
                description: 'MM7 comfort interval (0 - 4294967295).'
            mm7oversizelimit:
                type: int
                description: 'Maximum file size to scan (1 - 819200 kB).'
            mms-antispam-mass-log:
                type: str
                description: 'Enable/disable logging for MMS antispam mass.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-av-block-log:
                type: str
                description: 'Enable/disable logging for MMS antivirus file blocking.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-av-oversize-log:
                type: str
                description: 'Enable/disable logging for MMS antivirus oversize file blocking.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-av-virus-log:
                type: str
                description: 'Enable/disable logging for MMS antivirus scanning.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-carrier-endpoint-filter-log:
                type: str
                description: 'Enable/disable logging for MMS end point filter blocking.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-checksum-log:
                type: str
                description: 'Enable/disable MMS content checksum logging.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-checksum-table:
                type: str
                description: 'MMS content checksum table ID.'
            mms-notification-log:
                type: str
                description: 'Enable/disable logging for MMS notification messages.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-web-content-log:
                type: str
                description: 'Enable/disable logging for MMS web content blocking.'
                choices:
                    - 'disable'
                    - 'enable'
            mmsbwordthreshold:
                type: int
                description: 'MMS banned word threshold.'
            name:
                type: str
                description: 'Profile name.'
            notif-msisdn:
                description: 'Notif-Msisdn.'
                type: list
                suboptions:
                    msisdn:
                        type: str
                        description: 'Recipient MSISDN.'
                    threshold:
                        description: 'Thresholds on which this MSISDN will receive an alert.'
                        type: list
                        choices:
                         - flood-thresh-1
                         - flood-thresh-2
                         - flood-thresh-3
                         - dupe-thresh-1
                         - dupe-thresh-2
                         - dupe-thresh-3
            remove-blocked-const-length:
                type: str
                description: 'Enable/disable MMS replacement of blocked file constant length.'
                choices:
                    - 'disable'
                    - 'enable'
            replacemsg-group:
                type: str
                description: 'Replacement message group.'

'''

EXAMPLES = '''
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
    - name: retrieve all the MMS profiles
      fmgr_fact:
        facts:
            selector: 'firewall_mmsprofile'
            params:
                adom: 'FortiCarrier' # FortiCarrier only object, need a FortiCarrier adom
                mms-profile: ''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure MMS profiles.
      fmgr_firewall_mmsprofile:
         bypass_validation: False
         adom: FortiCarrier # FortiCarrier only object, need a FortiCarrier adom
         state: present
         firewall_mmsprofile:
            comment: 'ansible-comment'
            #extended-utm-log: disable 
            mm1:
              - avmonitor
              - block
              - oversize
              - quarantine
              - scan
              - avquery
              - bannedword
              - no-content-summary
              - archive-summary
              - archive-full
              - carrier-endpoint-bwl
              - remove-blocked
              - chunkedbypass
              - clientcomfort
              - servercomfort
              - strict-file
              - mms-checksum
            mm3:
              - avmonitor
              - block
              - oversize
              - quarantine
              - scan
              - avquery
              - bannedword
              - no-content-summary
              - archive-summary
              - archive-full
              - carrier-endpoint-bwl
              - remove-blocked
              - fragmail
              - splice
              - mms-checksum
            mm4:
              - avmonitor
              - block
              - oversize
              - quarantine
              - scan
              - avquery
              - bannedword
              - no-content-summary
              - archive-summary
              - archive-full
              - carrier-endpoint-bwl
              - remove-blocked
              - fragmail
              - splice
              - mms-checksum
            mm7:
              - avmonitor
              - block
              - oversize
              - quarantine
              - scan
              - avquery
              - bannedword
              - no-content-summary
              - archive-summary
              - archive-full
              - carrier-endpoint-bwl
              - remove-blocked
              - chunkedbypass
              - clientcomfort
              - servercomfort
              - strict-file
              - mms-checksum
            name: 'ansible-test'

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
        '/pm/config/adom/{adom}/obj/firewall/mms-profile',
        '/pm/config/global/obj/firewall/mms-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
        '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
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
        'firewall_mmsprofile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            },
            'options': {
                'avnotificationtable': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'bwordtable': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'carrier-endpoint-prefix': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'carrier-endpoint-prefix-range-max': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'carrier-endpoint-prefix-range-min': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'carrier-endpoint-prefix-string': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'carrierendpointbwltable': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'mm1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'choices': [
                        'avmonitor',
                        'block',
                        'oversize',
                        'quarantine',
                        'scan',
                        'avquery',
                        'bannedword',
                        'no-content-summary',
                        'archive-summary',
                        'archive-full',
                        'carrier-endpoint-bwl',
                        'remove-blocked',
                        'chunkedbypass',
                        'clientcomfort',
                        'servercomfort',
                        'strict-file',
                        'mms-checksum'
                    ]
                },
                'mm1-addr-hdr': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'mm1-addr-source': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'http-header',
                        'cookie'
                    ],
                    'type': 'str'
                },
                'mm1-convert-hex': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mm1-outbreak-prevention': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disabled',
                        'files',
                        'full-archive'
                    ],
                    'type': 'str'
                },
                'mm1-retr-dupe': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mm1-retrieve-scan': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mm1comfortamount': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm1comfortinterval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm1oversizelimit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'choices': [
                        'avmonitor',
                        'block',
                        'oversize',
                        'quarantine',
                        'scan',
                        'avquery',
                        'bannedword',
                        'no-content-summary',
                        'archive-summary',
                        'archive-full',
                        'carrier-endpoint-bwl',
                        'remove-blocked',
                        'fragmail',
                        'splice',
                        'mms-checksum'
                    ]
                },
                'mm3-outbreak-prevention': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disabled',
                        'files',
                        'full-archive'
                    ],
                    'type': 'str'
                },
                'mm3oversizelimit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm4': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'choices': [
                        'avmonitor',
                        'block',
                        'oversize',
                        'quarantine',
                        'scan',
                        'avquery',
                        'bannedword',
                        'no-content-summary',
                        'archive-summary',
                        'archive-full',
                        'carrier-endpoint-bwl',
                        'remove-blocked',
                        'fragmail',
                        'splice',
                        'mms-checksum'
                    ]
                },
                'mm4-outbreak-prevention': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disabled',
                        'files',
                        'full-archive'
                    ],
                    'type': 'str'
                },
                'mm4oversizelimit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm7': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'choices': [
                        'avmonitor',
                        'block',
                        'oversize',
                        'quarantine',
                        'scan',
                        'avquery',
                        'bannedword',
                        'no-content-summary',
                        'archive-summary',
                        'archive-full',
                        'carrier-endpoint-bwl',
                        'remove-blocked',
                        'chunkedbypass',
                        'clientcomfort',
                        'servercomfort',
                        'strict-file',
                        'mms-checksum'
                    ]
                },
                'mm7-addr-hdr': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'mm7-addr-source': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'http-header',
                        'cookie'
                    ],
                    'type': 'str'
                },
                'mm7-convert-hex': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mm7-outbreak-prevention': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disabled',
                        'files',
                        'full-archive'
                    ],
                    'type': 'str'
                },
                'mm7comfortamount': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm7comfortinterval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mm7oversizelimit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mms-antispam-mass-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-av-block-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-av-oversize-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-av-virus-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-carrier-endpoint-filter-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-checksum-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-checksum-table': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'mms-notification-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-web-content-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mmsbwordthreshold': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'notif-msisdn': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'msisdn': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'threshold': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'flood-thresh-1',
                                'flood-thresh-2',
                                'flood-thresh-3',
                                'dupe-thresh-1',
                                'dupe-thresh-2',
                                'dupe-thresh-3'
                            ]
                        }
                    }
                },
                'remove-blocked-const-length': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_mmsprofile'),
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
