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
module: fmgr_wtpprofile_lan
short_description: WTP LAN port mapping.
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
    wtp-profile:
        description: the parameter (wtp-profile) in requested url
        type: str
        required: true
    wtpprofile_lan:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            port-mode:
                type: str
                description: 'LAN port mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port-ssid:
                type: str
                description: 'Bridge LAN port to SSID.'
            port1-mode:
                type: str
                description: 'LAN port 1 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port1-ssid:
                type: str
                description: 'Bridge LAN port 1 to SSID.'
            port2-mode:
                type: str
                description: 'LAN port 2 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port2-ssid:
                type: str
                description: 'Bridge LAN port 2 to SSID.'
            port3-mode:
                type: str
                description: 'LAN port 3 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port3-ssid:
                type: str
                description: 'Bridge LAN port 3 to SSID.'
            port4-mode:
                type: str
                description: 'LAN port 4 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port4-ssid:
                type: str
                description: 'Bridge LAN port 4 to SSID.'
            port5-mode:
                type: str
                description: 'LAN port 5 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port5-ssid:
                type: str
                description: 'Bridge LAN port 5 to SSID.'
            port6-mode:
                type: str
                description: 'LAN port 6 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port6-ssid:
                type: str
                description: 'Bridge LAN port 6 to SSID.'
            port7-mode:
                type: str
                description: 'LAN port 7 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port7-ssid:
                type: str
                description: 'Bridge LAN port 7 to SSID.'
            port8-mode:
                type: str
                description: 'LAN port 8 mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port8-ssid:
                type: str
                description: 'Bridge LAN port 8 to SSID.'
            port-esl-mode:
                type: str
                description: 'ESL port mode.'
                choices:
                    - 'offline'
                    - 'bridge-to-wan'
                    - 'bridge-to-ssid'
                    - 'nat-to-wan'
            port-esl-ssid:
                type: str
                description: 'Bridge ESL port to SSID.'

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
    - name: WTP LAN port mapping.
      fmgr_wtpprofile_lan:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wtp-profile: <your own value>
         wtpprofile_lan:
            port-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port-ssid: <value of string>
            port1-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port1-ssid: <value of string>
            port2-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port2-ssid: <value of string>
            port3-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port3-ssid: <value of string>
            port4-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port4-ssid: <value of string>
            port5-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port5-ssid: <value of string>
            port6-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port6-ssid: <value of string>
            port7-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port7-ssid: <value of string>
            port8-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port8-ssid: <value of string>
            port-esl-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
            port-esl-ssid: <value of string>

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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lan',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lan'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lan/{lan}',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lan/{lan}'
    ]

    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'wtp-profile': {
            'required': True,
            'type': 'str'
        },
        'wtpprofile_lan': {
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
                'port-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port-ssid': {
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
                'port1-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port1-ssid': {
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
                'port2-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port2-ssid': {
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
                'port3-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port3-ssid': {
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
                'port4-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port4-ssid': {
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
                'port5-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port5-ssid': {
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
                'port6-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port6-ssid': {
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
                'port7-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port7-ssid': {
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
                'port8-mode': {
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
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port8-ssid': {
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
                'port-esl-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'offline',
                        'bridge-to-wan',
                        'bridge-to-ssid',
                        'nat-to-wan'
                    ],
                    'type': 'str'
                },
                'port-esl-ssid': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_lan'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
