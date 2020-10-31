#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
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
module: fmgr_system_logfetch_clientprofile
short_description: Log-fetch client profile settings.
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
    system_logfetch_clientprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            client-adom:
                type: str
                description: 'Log-fetch client sides adom name.'
            data-range:
                type: str
                default: 'custom'
                description:
                 - 'Data-range for fetched logs.'
                 - 'custom - Specify some other date and time range.'
                choices:
                    - 'custom'
            data-range-value:
                type: int
                default: 10
                description: 'Last n days or hours.'
            device-filter:
                description: no description
                type: list
                suboptions:
                    adom:
                        type: str
                        default: '*'
                        description: 'Adom name.'
                    device:
                        type: str
                        default: '*'
                        description: 'Device name or Serial number.'
                    id:
                        type: int
                        default: 0
                        description: 'Add or edit a device filter.'
                    vdom:
                        type: str
                        default: '*'
                        description: 'Vdom filters.'
            end-time:
                description: no description
                type: str
            id:
                type: int
                default: 0
                description: 'Log-fetch client profile ID.'
            index-fetch-logs:
                type: str
                default: 'enable'
                description:
                 - 'Enable/Disable indexing logs automatically after fetching logs.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            log-filter:
                description: no description
                type: list
                suboptions:
                    field:
                        type: str
                        description: 'Field name.'
                    id:
                        type: int
                        default: 0
                        description: 'Log filter ID.'
                    oper:
                        type: str
                        default: '='
                        description:
                         - 'Field filter operator.'
                         - '&lt; - =Less than or equal to'
                         - '&gt; - =Greater than or equal to'
                         - 'contain - Contain'
                         - 'not-contain - Not contain'
                         - 'match - Match (expression)'
                        choices:
                            - '='
                            - '!='
                            - '<'
                            - '>'
                            - '<='
                            - '>='
                            - 'contain'
                            - 'not-contain'
                            - 'match'
                    value:
                        type: str
                        description: 'Field filter operand or free-text matching expression.'
            log-filter-logic:
                type: str
                default: 'or'
                description:
                 - 'And/Or logic for log-filters.'
                 - 'and - Logic And.'
                 - 'or - Logic Or.'
                choices:
                    - 'and'
                    - 'or'
            log-filter-status:
                type: str
                default: 'disable'
                description:
                 - 'Enable/Disable log-filter.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'Name of log-fetch client profile.'
            password:
                description: no description
                type: str
            secure-connection:
                type: str
                default: 'enable'
                description:
                 - 'Enable/Disable protecting log-fetch connection with TLS/SSL.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            server-adom:
                type: str
                description: 'Log-fetch server sides adom name.'
            server-ip:
                type: str
                default: '0.0.0.0'
                description: 'Log-fetch server IP address.'
            start-time:
                description: no description
                type: str
            sync-adom-config:
                type: str
                default: 'disable'
                description:
                 - 'Enable/Disable sync adom related config.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            user:
                type: str
                description: 'Log-fetch server login username.'

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
    - name: Log-fetch client profile settings.
      fmgr_system_logfetch_clientprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         state: <value in [present, absent]>
         system_logfetch_clientprofile:
            client-adom: <value of string>
            data-range: <value in [custom]>
            data-range-value: <value of integer>
            device-filter:
              -
                  adom: <value of string>
                  device: <value of string>
                  id: <value of integer>
                  vdom: <value of string>
            end-time: <value of string>
            id: <value of integer>
            index-fetch-logs: <value in [disable, enable]>
            log-filter:
              -
                  field: <value of string>
                  id: <value of integer>
                  oper: <value in [=, !=, <, ...]>
                  value: <value of string>
            log-filter-logic: <value in [and, or]>
            log-filter-status: <value in [disable, enable]>
            name: <value of string>
            password: <value of string>
            secure-connection: <value in [disable, enable]>
            server-adom: <value of string>
            server-ip: <value of string>
            start-time: <value of string>
            sync-adom-config: <value in [disable, enable]>
            user: <value of string>

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
        '/cli/global/system/log-fetch/client-profile'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log-fetch/client-profile/{client-profile}'
    ]

    url_params = []
    module_primary_key = 'id'
    module_arg_spec = {
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
        'system_logfetch_clientprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                'client-adom': {
                    'required': False,
                    'type': 'str'
                },
                'data-range': {
                    'required': False,
                    'choices': [
                        'custom'
                    ],
                    'type': 'str'
                },
                'data-range-value': {
                    'required': False,
                    'type': 'int'
                },
                'device-filter': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'adom': {
                            'required': False,
                            'type': 'str'
                        },
                        'device': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'vdom': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'end-time': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'index-fetch-logs': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-filter': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'field': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'oper': {
                            'required': False,
                            'choices': [
                                '=',
                                '!=',
                                '<',
                                '>',
                                '<=',
                                '>=',
                                'contain',
                                'not-contain',
                                'match'
                            ],
                            'type': 'str'
                        },
                        'value': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'log-filter-logic': {
                    'required': False,
                    'choices': [
                        'and',
                        'or'
                    ],
                    'type': 'str'
                },
                'log-filter-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'password': {
                    'required': False,
                    'type': 'str'
                },
                'secure-connection': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'server-adom': {
                    'required': False,
                    'type': 'str'
                },
                'server-ip': {
                    'required': False,
                    'type': 'str'
                },
                'start-time': {
                    'required': False,
                    'type': 'str'
                },
                'sync-adom-config': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_logfetch_clientprofile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
