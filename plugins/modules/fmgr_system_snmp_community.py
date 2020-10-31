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
module: fmgr_system_snmp_community
short_description: SNMP community configuration.
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
    system_snmp_community:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            events:
                description: no description
                type: list
                choices:
                 - disk_low
                 - ha_switch
                 - intf_ip_chg
                 - sys_reboot
                 - cpu_high
                 - mem_low
                 - log-alert
                 - log-rate
                 - log-data-rate
                 - lic-gbday
                 - lic-dev-quota
                 - cpu-high-exclude-nice
            hosts:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        default: 0
                        description: 'Host entry ID.'
                    interface:
                        type: str
                        description: 'Allow interface name.'
                    ip:
                        type: str
                        default: '0.0.0.0 0.0.0.0'
                        description: 'Allow host IP address.'
            hosts6:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        default: 0
                        description: 'Host entry ID.'
                    interface:
                        type: str
                        description: 'Allow interface name.'
                    ip:
                        type: str
                        default: '::/0'
                        description: 'Allow host IP address.'
            id:
                type: int
                default: 0
                description: 'Community ID.'
            name:
                type: str
                description: 'Community name.'
            query_v1_port:
                type: int
                default: 161
                description: 'SNMP v1 query port.'
            query_v1_status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable SNMP v1 query.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            query_v2c_port:
                type: int
                default: 161
                description: 'SNMP v2c query port.'
            query_v2c_status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable SNMP v2c query.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable community.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            trap_v1_rport:
                type: int
                default: 162
                description: 'SNMP v1 trap remote port.'
            trap_v1_status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable SNMP v1 trap.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            trap_v2c_rport:
                type: int
                default: 162
                description: 'SNMP v2c trap remote port.'
            trap_v2c_status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable SNMP v2c trap.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'

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
    - name: SNMP community configuration.
      fmgr_system_snmp_community:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         state: <value in [present, absent]>
         system_snmp_community:
            events:
              - disk_low
              - ha_switch
              - intf_ip_chg
              - sys_reboot
              - cpu_high
              - mem_low
              - log-alert
              - log-rate
              - log-data-rate
              - lic-gbday
              - lic-dev-quota
              - cpu-high-exclude-nice
            hosts:
              -
                  id: <value of integer>
                  interface: <value of string>
                  ip: <value of string>
            hosts6:
              -
                  id: <value of integer>
                  interface: <value of string>
                  ip: <value of string>
            id: <value of integer>
            name: <value of string>
            query_v1_port: <value of integer>
            query_v1_status: <value in [disable, enable]>
            query_v2c_port: <value of integer>
            query_v2c_status: <value in [disable, enable]>
            status: <value in [disable, enable]>
            trap_v1_rport: <value of integer>
            trap_v1_status: <value in [disable, enable]>
            trap_v2c_rport: <value of integer>
            trap_v2c_status: <value in [disable, enable]>

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
        '/cli/global/system/snmp/community'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/snmp/community/{community}'
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
        'system_snmp_community': {
            'required': False,
            'type': 'dict',
            'options': {
                'events': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'disk_low',
                        'ha_switch',
                        'intf_ip_chg',
                        'sys_reboot',
                        'cpu_high',
                        'mem_low',
                        'log-alert',
                        'log-rate',
                        'log-data-rate',
                        'lic-gbday',
                        'lic-dev-quota',
                        'cpu-high-exclude-nice'
                    ]
                },
                'hosts': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'interface': {
                            'required': False,
                            'type': 'str'
                        },
                        'ip': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'hosts6': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'interface': {
                            'required': False,
                            'type': 'str'
                        },
                        'ip': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'query_v1_port': {
                    'required': False,
                    'type': 'int'
                },
                'query_v1_status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'query_v2c_port': {
                    'required': False,
                    'type': 'int'
                },
                'query_v2c_status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trap_v1_rport': {
                    'required': False,
                    'type': 'int'
                },
                'trap_v1_status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trap_v2c_rport': {
                    'required': False,
                    'type': 'int'
                },
                'trap_v2c_status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_snmp_community'),
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
