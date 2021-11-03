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
module: fmgr_dlp_sensor
short_description: Configure DLP sensors.
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
    dlp_sensor:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: 'Comment.'
            dlp-log:
                type: str
                description: 'Enable/disable DLP logging.'
                choices:
                    - 'disable'
                    - 'enable'
            extended-log:
                type: str
                description: 'Enable/disable extended logging for data leak prevention.'
                choices:
                    - 'disable'
                    - 'enable'
            filter:
                description: 'Filter.'
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action to take with content that this DLP sensor matches.'
                        choices:
                            - 'log-only'
                            - 'block'
                            - 'exempt'
                            - 'ban'
                            - 'ban-sender'
                            - 'quarantine-ip'
                            - 'quarantine-port'
                            - 'none'
                            - 'allow'
                    archive:
                        type: str
                        description: 'Enable/disable DLP archiving.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'summary-only'
                    company-identifier:
                        type: str
                        description: 'Enter a company identifier watermark to match. Only watermarks that your company has placed on the files are matched.'
                    expiry:
                        type: str
                        description: 'Quarantine duration in days, hours, minutes format (dddhhmm).'
                    file-size:
                        type: int
                        description: 'Match files this size or larger (0 - 4294967295 kbytes).'
                    file-type:
                        type: str
                        description: 'Select the number of a DLP file pattern table to match.'
                    filter-by:
                        type: str
                        description: 'Select the type of content to match.'
                        choices:
                            - 'credit-card'
                            - 'ssn'
                            - 'regexp'
                            - 'file-type'
                            - 'file-size'
                            - 'fingerprint'
                            - 'watermark'
                            - 'encrypted'
                    fp-sensitivity:
                        type: str
                        description: 'Select a DLP file pattern sensitivity to match.'
                    id:
                        type: int
                        description: 'ID.'
                    match-percentage:
                        type: int
                        description: 'Percentage of fingerprints in the fingerprint databases designated with the selected fp-sensitivity to match.'
                    name:
                        type: str
                        description: 'Filter name.'
                    proto:
                        description: 'Check messages or files over one or more of these protocols.'
                        type: list
                        choices:
                         - imap
                         - smtp
                         - pop3
                         - ftp
                         - nntp
                         - mm1
                         - mm3
                         - mm4
                         - mm7
                         - mapi
                         - aim
                         - icq
                         - msn
                         - yahoo
                         - http-get
                         - http-post
                         - ssh
                         - cifs
                    regexp:
                        type: str
                        description: 'Enter a regular expression to match (max. 255 characters).'
                    severity:
                        type: str
                        description: 'Select the severity or threat level that matches this filter.'
                        choices:
                            - 'info'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        type: str
                        description: 'Select whether to check the content of messages (an email message) or files (downloaded files or email attachments).'
                        choices:
                            - 'file'
                            - 'message'
                    sensitivity:
                        type: str
                        description: 'Select a DLP file pattern sensitivity to match.'
            flow-based:
                type: str
                description: 'Enable/disable flow-based DLP.'
                choices:
                    - 'disable'
                    - 'enable'
            full-archive-proto:
                description: 'Protocols to always content archive.'
                type: list
                choices:
                 - imap
                 - smtp
                 - pop3
                 - ftp
                 - nntp
                 - mm1
                 - mm3
                 - mm4
                 - mm7
                 - mapi
                 - aim
                 - icq
                 - msn
                 - yahoo
                 - http-get
                 - http-post
                 - ssh
                 - cifs
            nac-quar-log:
                type: str
                description: 'Enable/disable NAC quarantine logging.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'Name of the DLP sensor.'
            options:
                type: str
                description: 'Configure DLP options.'
                choices:
                    - 'strict-file'
            replacemsg-group:
                type: str
                description: 'Replacement message group used by this DLP sensor.'
            summary-proto:
                description: 'Protocols to always log summary.'
                type: list
                choices:
                 - imap
                 - smtp
                 - pop3
                 - ftp
                 - nntp
                 - mm1
                 - mm3
                 - mm4
                 - mm7
                 - mapi
                 - aim
                 - icq
                 - msn
                 - yahoo
                 - http-get
                 - http-post
                 - ssh
                 - cifs
            feature-set:
                type: str
                description: 'Flow/proxy feature set.'
                choices:
                    - 'proxy'
                    - 'flow'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure DLP sensors.
      fmgr_dlp_sensor:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         dlp_sensor:
            comment: <value of string>
            dlp-log: <value in [disable, enable]>
            extended-log: <value in [disable, enable]>
            filter:
              -
                  action: <value in [log-only, block, exempt, ...]>
                  archive: <value in [disable, enable, summary-only]>
                  company-identifier: <value of string>
                  expiry: <value of string>
                  file-size: <value of integer>
                  file-type: <value of string>
                  filter-by: <value in [credit-card, ssn, regexp, ...]>
                  fp-sensitivity: <value of string>
                  id: <value of integer>
                  match-percentage: <value of integer>
                  name: <value of string>
                  proto:
                    - imap
                    - smtp
                    - pop3
                    - ftp
                    - nntp
                    - mm1
                    - mm3
                    - mm4
                    - mm7
                    - mapi
                    - aim
                    - icq
                    - msn
                    - yahoo
                    - http-get
                    - http-post
                    - ssh
                    - cifs
                  regexp: <value of string>
                  severity: <value in [info, low, medium, ...]>
                  type: <value in [file, message]>
                  sensitivity: <value of string>
            flow-based: <value in [disable, enable]>
            full-archive-proto:
              - imap
              - smtp
              - pop3
              - ftp
              - nntp
              - mm1
              - mm3
              - mm4
              - mm7
              - mapi
              - aim
              - icq
              - msn
              - yahoo
              - http-get
              - http-post
              - ssh
              - cifs
            nac-quar-log: <value in [disable, enable]>
            name: <value of string>
            options: <value in [strict-file]>
            replacemsg-group: <value of string>
            summary-proto:
              - imap
              - smtp
              - pop3
              - ftp
              - nntp
              - mm1
              - mm3
              - mm4
              - mm7
              - mapi
              - aim
              - icq
              - msn
              - yahoo
              - http-get
              - http-post
              - ssh
              - cifs
            feature-set: <value in [proxy, flow]>

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
        '/pm/config/adom/{adom}/obj/dlp/sensor',
        '/pm/config/global/obj/dlp/sensor'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
        '/pm/config/global/obj/dlp/sensor/{sensor}'
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
        'dlp_sensor': {
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
                '7.0.0': True
            },
            'options': {
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'dlp-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
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
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'log-only',
                                'block',
                                'exempt',
                                'ban',
                                'ban-sender',
                                'quarantine-ip',
                                'quarantine-port',
                                'none',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'archive': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'summary-only'
                            ],
                            'type': 'str'
                        },
                        'company-identifier': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'expiry': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'file-size': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'file-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'filter-by': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'credit-card',
                                'ssn',
                                'regexp',
                                'file-type',
                                'file-size',
                                'fingerprint',
                                'watermark',
                                'encrypted'
                            ],
                            'type': 'str'
                        },
                        'fp-sensitivity': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'match-percentage': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'proto': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'imap',
                                'smtp',
                                'pop3',
                                'ftp',
                                'nntp',
                                'mm1',
                                'mm3',
                                'mm4',
                                'mm7',
                                'mapi',
                                'aim',
                                'icq',
                                'msn',
                                'yahoo',
                                'http-get',
                                'http-post',
                                'ssh',
                                'cifs'
                            ]
                        },
                        'regexp': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'info',
                                'low',
                                'medium',
                                'high',
                                'critical'
                            ],
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'file',
                                'message'
                            ],
                            'type': 'str'
                        },
                        'sensitivity': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'flow-based': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
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
                'full-archive-proto': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'imap',
                        'smtp',
                        'pop3',
                        'ftp',
                        'nntp',
                        'mm1',
                        'mm3',
                        'mm4',
                        'mm7',
                        'mapi',
                        'aim',
                        'icq',
                        'msn',
                        'yahoo',
                        'http-get',
                        'http-post',
                        'ssh',
                        'cifs'
                    ]
                },
                'nac-quar-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'options': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'strict-file'
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'summary-proto': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'imap',
                        'smtp',
                        'pop3',
                        'ftp',
                        'nntp',
                        'mm1',
                        'mm3',
                        'mm4',
                        'mm7',
                        'mapi',
                        'aim',
                        'icq',
                        'msn',
                        'yahoo',
                        'http-get',
                        'http-post',
                        'ssh',
                        'cifs'
                    ]
                },
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_sensor'),
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
