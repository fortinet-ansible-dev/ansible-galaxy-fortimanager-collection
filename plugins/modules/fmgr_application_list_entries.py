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
module: fmgr_application_list_entries
short_description: Application list entries.
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
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    list:
        description: the parameter (list) in requested url
        type: str
        required: true
    application_list_entries:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: 'Pass or block traffic, or reset connection for traffic from this application.'
                choices:
                    - 'pass'
                    - 'block'
                    - 'reset'
            application:
                description: no description
                type: int
            behavior:
                description: no description
                type: str
            category:
                type: str
                description: 'Category ID list.'
            id:
                type: int
                description: 'Entry ID.'
            log:
                type: str
                description: 'Enable/disable logging for this application list.'
                choices:
                    - 'disable'
                    - 'enable'
            log-packet:
                type: str
                description: 'Enable/disable packet logging.'
                choices:
                    - 'disable'
                    - 'enable'
            parameters:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: 'Parameter ID.'
                    value:
                        type: str
                        description: 'Parameter value.'
            per-ip-shaper:
                type: str
                description: 'Per-IP traffic shaper.'
            popularity:
                description: no description
                type: list
                choices:
                 - 1
                 - 2
                 - 3
                 - 4
                 - 5
            protocols:
                description: no description
                type: str
            quarantine:
                type: str
                description: 'Quarantine method.'
                choices:
                    - 'none'
                    - 'attacker'
            quarantine-expiry:
                type: str
                description: 'Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m, default = 5m). Requires quarantine set to attacker.'
            quarantine-log:
                type: str
                description: 'Enable/disable quarantine logging.'
                choices:
                    - 'disable'
                    - 'enable'
            rate-count:
                type: int
                description: 'Count of the rate.'
            rate-duration:
                type: int
                description: 'Duration (sec) of the rate.'
            rate-mode:
                type: str
                description: 'Rate limit mode.'
                choices:
                    - 'periodical'
                    - 'continuous'
            rate-track:
                type: str
                description: 'Track the packet protocol field.'
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
                    - 'dhcp-client-mac'
                    - 'dns-domain'
            risk:
                description: no description
                type: int
            session-ttl:
                type: int
                description: 'Session TTL (0 = default).'
            shaper:
                type: str
                description: 'Traffic shaper.'
            shaper-reverse:
                type: str
                description: 'Reverse traffic shaper.'
            sub-category:
                description: no description
                type: int
            technology:
                description: no description
                type: str
            vendor:
                description: no description
                type: str

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
    - name: Application list entries.
      fmgr_application_list_entries:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         list: <your own value>
         state: <value in [present, absent]>
         application_list_entries:
            action: <value in [pass, block, reset]>
            application: <value of integer>
            behavior: <value of string>
            category: <value of string>
            id: <value of integer>
            log: <value in [disable, enable]>
            log-packet: <value in [disable, enable]>
            parameters:
              -
                  id: <value of integer>
                  value: <value of string>
            per-ip-shaper: <value of string>
            popularity:
              - 1
              - 2
              - 3
              - 4
              - 5
            protocols: <value of string>
            quarantine: <value in [none, attacker]>
            quarantine-expiry: <value of string>
            quarantine-log: <value in [disable, enable]>
            rate-count: <value of integer>
            rate-duration: <value of integer>
            rate-mode: <value in [periodical, continuous]>
            rate-track: <value in [none, src-ip, dest-ip, ...]>
            risk: <value of integer>
            session-ttl: <value of integer>
            shaper: <value of string>
            shaper-reverse: <value of string>
            sub-category: <value of integer>
            technology: <value of string>
            vendor: <value of string>

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
        '/pm/config/adom/{adom}/obj/application/list/{list}/entries',
        '/pm/config/global/obj/application/list/{list}/entries'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
        '/pm/config/global/obj/application/list/{list}/entries/{entries}'
    ]

    url_params = ['adom', 'list']
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'list': {
            'required': True,
            'type': 'str'
        },
        'application_list_entries': {
            'required': False,
            'type': 'dict',
            'options': {
                'action': {
                    'required': False,
                    'choices': [
                        'pass',
                        'block',
                        'reset'
                    ],
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'type': 'int'
                },
                'behavior': {
                    'required': False,
                    'type': 'str'
                },
                'category': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-packet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'parameters': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'value': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'popularity': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        '1',
                        '2',
                        '3',
                        '4',
                        '5'
                    ]
                },
                'protocols': {
                    'required': False,
                    'type': 'str'
                },
                'quarantine': {
                    'required': False,
                    'choices': [
                        'none',
                        'attacker'
                    ],
                    'type': 'str'
                },
                'quarantine-expiry': {
                    'required': False,
                    'type': 'str'
                },
                'quarantine-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-count': {
                    'required': False,
                    'type': 'int'
                },
                'rate-duration': {
                    'required': False,
                    'type': 'int'
                },
                'rate-mode': {
                    'required': False,
                    'choices': [
                        'periodical',
                        'continuous'
                    ],
                    'type': 'str'
                },
                'rate-track': {
                    'required': False,
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip',
                        'dhcp-client-mac',
                        'dns-domain'
                    ],
                    'type': 'str'
                },
                'risk': {
                    'required': False,
                    'type': 'int'
                },
                'session-ttl': {
                    'required': False,
                    'type': 'int'
                },
                'shaper': {
                    'required': False,
                    'type': 'str'
                },
                'shaper-reverse': {
                    'required': False,
                    'type': 'str'
                },
                'sub-category': {
                    'required': False,
                    'type': 'int'
                },
                'technology': {
                    'required': False,
                    'type': 'str'
                },
                'vendor': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_list_entries'),
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
