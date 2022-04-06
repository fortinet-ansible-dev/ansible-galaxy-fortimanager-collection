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
module: fmgr_gtp_messagefilterv0v1
short_description: Message filter for GTPv0/v1 messages.
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
    gtp_messagefilterv0v1:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            create-mbms:
                type: str
                description: 'GTPv1 create MBMS context (req 100, resp 101).'
                choices:
                    - 'allow'
                    - 'deny'
            create-pdp:
                type: str
                description: 'Create PDP context (req 16, resp 17).'
                choices:
                    - 'allow'
                    - 'deny'
            data-record:
                type: str
                description: 'Data record transfer (req 240, resp 241).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-aa-pdp:
                type: str
                description: 'GTPv0 delete AA PDP context (req 24, resp 25).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-mbms:
                type: str
                description: 'GTPv1 delete MBMS context (req 104, resp 105).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-pdp:
                type: str
                description: 'Delete PDP context (req 20, resp 21).'
                choices:
                    - 'allow'
                    - 'deny'
            echo:
                type: str
                description: 'Echo (req 1, resp 2).'
                choices:
                    - 'allow'
                    - 'deny'
            end-marker:
                type: str
                description: 'GTPv1 End marker (254).'
                choices:
                    - 'allow'
                    - 'deny'
            error-indication:
                type: str
                description: 'Error indication (26).'
                choices:
                    - 'allow'
                    - 'deny'
            failure-report:
                type: str
                description: 'Failure report (req 34, resp 35).'
                choices:
                    - 'allow'
                    - 'deny'
            fwd-relocation:
                type: str
                description: 'GTPv1 forward relocation (req 53, resp 54, complete 55, complete ack 59).'
                choices:
                    - 'allow'
                    - 'deny'
            fwd-srns-context:
                type: str
                description: 'GTPv1 forward SRNS (context 58, context ack 60).'
                choices:
                    - 'allow'
                    - 'deny'
            gtp-pdu:
                type: str
                description: 'PDU (255).'
                choices:
                    - 'allow'
                    - 'deny'
            identification:
                type: str
                description: 'Identification (req 48, resp 49).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-de-registration:
                type: str
                description: 'GTPv1 MBMS de-registration (req 114, resp 115).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-notification:
                type: str
                description: 'GTPv1 MBMS notification (req 96, resp 97, reject req 98. reject resp 99).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-registration:
                type: str
                description: 'GTPv1 MBMS registration (req 112, resp 113).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-session-start:
                type: str
                description: 'GTPv1 MBMS session start (req 116, resp 117).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-session-stop:
                type: str
                description: 'GTPv1 MBMS session stop (req 118, resp 119).'
                choices:
                    - 'allow'
                    - 'deny'
            mbms-session-update:
                type: str
                description: 'GTPv1 MBMS session update (req 120, resp 121).'
                choices:
                    - 'allow'
                    - 'deny'
            ms-info-change-notif:
                type: str
                description: 'GTPv1 MS info change notification (req 128, resp 129).'
                choices:
                    - 'allow'
                    - 'deny'
            name:
                type: str
                description: 'Message filter name.'
            node-alive:
                type: str
                description: 'Node alive (req 4, resp 5).'
                choices:
                    - 'allow'
                    - 'deny'
            note-ms-present:
                type: str
                description: 'Note MS GPRS present (req 36, resp 37).'
                choices:
                    - 'allow'
                    - 'deny'
            pdu-notification:
                type: str
                description: 'PDU notification (req 27, resp 28, reject req 29, reject resp 30).'
                choices:
                    - 'allow'
                    - 'deny'
            ran-info:
                type: str
                description: 'GTPv1 RAN information relay (70).'
                choices:
                    - 'allow'
                    - 'deny'
            redirection:
                type: str
                description: 'Redirection (req 6, resp 7).'
                choices:
                    - 'allow'
                    - 'deny'
            relocation-cancel:
                type: str
                description: 'GTPv1 relocation cancel (req 56, resp 57).'
                choices:
                    - 'allow'
                    - 'deny'
            send-route:
                type: str
                description: 'Send routing information for GPRS (req 32, resp 33).'
                choices:
                    - 'allow'
                    - 'deny'
            sgsn-context:
                type: str
                description: 'SGSN context (req 50, resp 51, ack 52).'
                choices:
                    - 'allow'
                    - 'deny'
            support-extension:
                type: str
                description: 'GTPv1 supported extension headers notify (31).'
                choices:
                    - 'allow'
                    - 'deny'
            unknown-message:
                type: str
                description: 'Allow or Deny unknown messages.'
                choices:
                    - 'allow'
                    - 'deny'
            unknown-message-white-list:
                description: 'White list (to allow) of unknown messages.'
                type: int
            update-mbms:
                type: str
                description: 'GTPv1 update MBMS context (req 102, resp 103).'
                choices:
                    - 'allow'
                    - 'deny'
            update-pdp:
                type: str
                description: 'Update PDP context (req 18, resp 19).'
                choices:
                    - 'allow'
                    - 'deny'
            v0-create-aa-pdp--v1-init-pdp-ctx:
                type: str
                description: 'GTPv0 create AA PDP context (req 22, resp 23); Or GTPv1 initiate PDP context (req 22, resp 23).'
                choices:
                    - 'deny'
                    - 'allow'
            version-not-support:
                type: str
                description: 'Version not supported (3).'
                choices:
                    - 'allow'
                    - 'deny'

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
    - name: Message filter for GTPv0/v1 messages.
      fmgr_gtp_messagefilterv0v1:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         gtp_messagefilterv0v1:
            create-mbms: <value in [allow, deny]>
            create-pdp: <value in [allow, deny]>
            data-record: <value in [allow, deny]>
            delete-aa-pdp: <value in [allow, deny]>
            delete-mbms: <value in [allow, deny]>
            delete-pdp: <value in [allow, deny]>
            echo: <value in [allow, deny]>
            end-marker: <value in [allow, deny]>
            error-indication: <value in [allow, deny]>
            failure-report: <value in [allow, deny]>
            fwd-relocation: <value in [allow, deny]>
            fwd-srns-context: <value in [allow, deny]>
            gtp-pdu: <value in [allow, deny]>
            identification: <value in [allow, deny]>
            mbms-de-registration: <value in [allow, deny]>
            mbms-notification: <value in [allow, deny]>
            mbms-registration: <value in [allow, deny]>
            mbms-session-start: <value in [allow, deny]>
            mbms-session-stop: <value in [allow, deny]>
            mbms-session-update: <value in [allow, deny]>
            ms-info-change-notif: <value in [allow, deny]>
            name: <value of string>
            node-alive: <value in [allow, deny]>
            note-ms-present: <value in [allow, deny]>
            pdu-notification: <value in [allow, deny]>
            ran-info: <value in [allow, deny]>
            redirection: <value in [allow, deny]>
            relocation-cancel: <value in [allow, deny]>
            send-route: <value in [allow, deny]>
            sgsn-context: <value in [allow, deny]>
            support-extension: <value in [allow, deny]>
            unknown-message: <value in [allow, deny]>
            unknown-message-white-list: <value of integer>
            update-mbms: <value in [allow, deny]>
            update-pdp: <value in [allow, deny]>
            v0-create-aa-pdp--v1-init-pdp-ctx: <value in [deny, allow]>
            version-not-support: <value in [allow, deny]>

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
        '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1',
        '/pm/config/global/obj/gtp/message-filter-v0v1'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
        '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
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
        'gtp_messagefilterv0v1': {
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
                'create-mbms': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'create-pdp': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'data-record': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'delete-aa-pdp': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'delete-mbms': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'delete-pdp': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'echo': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'end-marker': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'error-indication': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'failure-report': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'fwd-relocation': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'fwd-srns-context': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'gtp-pdu': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'identification': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-de-registration': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-notification': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-registration': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-session-start': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-session-stop': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'mbms-session-update': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'ms-info-change-notif': {
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
                        'allow',
                        'deny'
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
                'node-alive': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'note-ms-present': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'pdu-notification': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'ran-info': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'redirection': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'relocation-cancel': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'send-route': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'sgsn-context': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'support-extension': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'unknown-message': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'unknown-message-white-list': {
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
                'update-mbms': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'update-pdp': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'v0-create-aa-pdp--v1-init-pdp-ctx': {
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
                        'deny',
                        'allow'
                    ],
                    'type': 'str'
                },
                'version-not-support': {
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
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'gtp_messagefilterv0v1'),
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
