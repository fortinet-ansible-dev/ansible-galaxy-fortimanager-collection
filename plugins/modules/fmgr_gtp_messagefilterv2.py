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
module: fmgr_gtp_messagefilterv2
short_description: Message filter for GTPv2 messages.
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
    gtp_messagefilterv2:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            bearer-resource-cmd-fail:
                type: str
                description: 'Bearer resource (command 68, failure indication 69).'
                choices:
                    - 'allow'
                    - 'deny'
            change-notification:
                type: str
                description: 'Change notification (req 38, resp 39).'
                choices:
                    - 'allow'
                    - 'deny'
            create-bearer:
                type: str
                description: 'Create bearer (req 95, resp 96).'
                choices:
                    - 'allow'
                    - 'deny'
            create-session:
                type: str
                description: 'Create session (req 32, resp 33).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-bearer-cmd-fail:
                type: str
                description: 'Delete bearer (command 66, failure indication 67).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-bearer-req-resp:
                type: str
                description: 'Delete bearer (req 99, resp 100).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-pdn-connection-set:
                type: str
                description: 'Delete PDN connection set (req 101, resp 102).'
                choices:
                    - 'allow'
                    - 'deny'
            delete-session:
                type: str
                description: 'Delete session (req 36, resp 37).'
                choices:
                    - 'allow'
                    - 'deny'
            echo:
                type: str
                description: 'Echo (req 1, resp 2).'
                choices:
                    - 'allow'
                    - 'deny'
            modify-bearer-cmd-fail:
                type: str
                description: 'Modify bearer (command 64 , failure indication 65).'
                choices:
                    - 'allow'
                    - 'deny'
            modify-bearer-req-resp:
                type: str
                description: 'Modify bearer (req 34, resp 35).'
                choices:
                    - 'allow'
                    - 'deny'
            name:
                type: str
                description: 'Message filter name.'
            resume:
                type: str
                description: 'Resume (notify 164 , ack 165).'
                choices:
                    - 'allow'
                    - 'deny'
            suspend:
                type: str
                description: 'Suspend (notify 162, ack 163).'
                choices:
                    - 'allow'
                    - 'deny'
            trace-session:
                type: str
                description: 'Trace session (activation 71, deactivation 72).'
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
            update-bearer:
                type: str
                description: 'Update bearer (req 97, resp 98).'
                choices:
                    - 'allow'
                    - 'deny'
            update-pdn-connection-set:
                type: str
                description: 'Update PDN connection set (req 200, resp 201).'
                choices:
                    - 'allow'
                    - 'deny'
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
    - name: Message filter for GTPv2 messages.
      fmgr_gtp_messagefilterv2:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         gtp_messagefilterv2:
            bearer-resource-cmd-fail: <value in [allow, deny]>
            change-notification: <value in [allow, deny]>
            create-bearer: <value in [allow, deny]>
            create-session: <value in [allow, deny]>
            delete-bearer-cmd-fail: <value in [allow, deny]>
            delete-bearer-req-resp: <value in [allow, deny]>
            delete-pdn-connection-set: <value in [allow, deny]>
            delete-session: <value in [allow, deny]>
            echo: <value in [allow, deny]>
            modify-bearer-cmd-fail: <value in [allow, deny]>
            modify-bearer-req-resp: <value in [allow, deny]>
            name: <value of string>
            resume: <value in [allow, deny]>
            suspend: <value in [allow, deny]>
            trace-session: <value in [allow, deny]>
            unknown-message: <value in [allow, deny]>
            unknown-message-white-list: <value of integer>
            update-bearer: <value in [allow, deny]>
            update-pdn-connection-set: <value in [allow, deny]>
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
        '/pm/config/adom/{adom}/obj/gtp/message-filter-v2',
        '/pm/config/global/obj/gtp/message-filter-v2'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
        '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
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
        'gtp_messagefilterv2': {
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
                'bearer-resource-cmd-fail': {
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
                'change-notification': {
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
                'create-bearer': {
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
                'create-session': {
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
                'delete-bearer-cmd-fail': {
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
                'delete-bearer-req-resp': {
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
                'delete-pdn-connection-set': {
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
                'delete-session': {
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
                'modify-bearer-cmd-fail': {
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
                'modify-bearer-req-resp': {
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
                'resume': {
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
                'suspend': {
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
                'trace-session': {
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
                'update-bearer': {
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
                'update-pdn-connection-set': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'gtp_messagefilterv2'),
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
