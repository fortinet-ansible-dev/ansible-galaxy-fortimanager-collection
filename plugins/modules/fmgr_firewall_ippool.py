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
module: fmgr_firewall_ippool
short_description: Configure IPv4 IP pools.
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
    firewall_ippool:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            arp-intf:
                type: str
                description: 'Select an interface from available options that will reply to ARP requests. (If blank, any is selected).'
            arp-reply:
                type: str
                description: 'Enable/disable replying to ARP requests when an IP Pool is added to a policy (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            associated-interface:
                type: str
                description: 'Associated interface name.'
            block-size:
                type: int
                description: 'Number of addresses in a block (64 to 4096, default = 128).'
            comments:
                type: str
                description: 'Comment.'
            dynamic_mapping:
                description: no description
                type: list
                suboptions:
                    _scope:
                        description: no description
                        type: list
                        suboptions:
                            name:
                                type: str
                                description: no description
                            vdom:
                                type: str
                                description: no description
                    arp-intf:
                        type: str
                        description: no description
                    arp-reply:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    associated-interface:
                        type: str
                        description: no description
                    block-size:
                        type: int
                        description: no description
                    comments:
                        type: str
                        description: no description
                    endip:
                        type: str
                        description: no description
                    num-blocks-per-user:
                        type: int
                        description: no description
                    pba-timeout:
                        type: int
                        description: no description
                    permit-any-host:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    source-endip:
                        type: str
                        description: no description
                    source-startip:
                        type: str
                        description: no description
                    startip:
                        type: str
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'overload'
                            - 'one-to-one'
                            - 'fixed-port-range'
                            - 'port-block-allocation'
            endip:
                type: str
                description: 'Final IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
            name:
                type: str
                description: 'IP pool name.'
            num-blocks-per-user:
                type: int
                description: 'Number of addresses blocks that can be used by a user (1 to 128, default = 8).'
            pba-timeout:
                type: int
                description: 'Port block allocation timeout (seconds).'
            permit-any-host:
                type: str
                description: 'Enable/disable full cone NAT.'
                choices:
                    - 'disable'
                    - 'enable'
            source-endip:
                type: str
                description: 'Final IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
            source-startip:
                type: str
                description: 'First IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
            startip:
                type: str
                description: 'First IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
            type:
                type: str
                description: 'IP pool type (overload, one-to-one, fixed port range, or port block allocation).'
                choices:
                    - 'overload'
                    - 'one-to-one'
                    - 'fixed-port-range'
                    - 'port-block-allocation'

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
    - name: Configure IPv4 IP pools.
      fmgr_firewall_ippool:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_ippool:
            arp-intf: <value of string>
            arp-reply: <value in [disable, enable]>
            associated-interface: <value of string>
            block-size: <value of integer>
            comments: <value of string>
            dynamic_mapping:
              -
                  _scope:
                    -
                        name: <value of string>
                        vdom: <value of string>
                  arp-intf: <value of string>
                  arp-reply: <value in [disable, enable]>
                  associated-interface: <value of string>
                  block-size: <value of integer>
                  comments: <value of string>
                  endip: <value of string>
                  num-blocks-per-user: <value of integer>
                  pba-timeout: <value of integer>
                  permit-any-host: <value in [disable, enable]>
                  source-endip: <value of string>
                  source-startip: <value of string>
                  startip: <value of string>
                  type: <value in [overload, one-to-one, fixed-port-range, ...]>
            endip: <value of string>
            name: <value of string>
            num-blocks-per-user: <value of integer>
            pba-timeout: <value of integer>
            permit-any-host: <value in [disable, enable]>
            source-endip: <value of string>
            source-startip: <value of string>
            startip: <value of string>
            type: <value in [overload, one-to-one, fixed-port-range, ...]>

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
        '/pm/config/adom/{adom}/obj/firewall/ippool',
        '/pm/config/global/obj/firewall/ippool'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
        '/pm/config/global/obj/firewall/ippool/{ippool}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'firewall_ippool': {
            'required': False,
            'type': 'dict',
            'options': {
                'arp-intf': {
                    'required': False,
                    'type': 'str'
                },
                'arp-reply': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'associated-interface': {
                    'required': False,
                    'type': 'str'
                },
                'block-size': {
                    'required': False,
                    'type': 'int'
                },
                'comments': {
                    'required': False,
                    'type': 'str'
                },
                'dynamic_mapping': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'required': False,
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': False,
                                    'type': 'str'
                                },
                                'vdom': {
                                    'required': False,
                                    'type': 'str'
                                }
                            }
                        },
                        'arp-intf': {
                            'required': False,
                            'type': 'str'
                        },
                        'arp-reply': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'associated-interface': {
                            'required': False,
                            'type': 'str'
                        },
                        'block-size': {
                            'required': False,
                            'type': 'int'
                        },
                        'comments': {
                            'required': False,
                            'type': 'str'
                        },
                        'endip': {
                            'required': False,
                            'type': 'str'
                        },
                        'num-blocks-per-user': {
                            'required': False,
                            'type': 'int'
                        },
                        'pba-timeout': {
                            'required': False,
                            'type': 'int'
                        },
                        'permit-any-host': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'source-endip': {
                            'required': False,
                            'type': 'str'
                        },
                        'source-startip': {
                            'required': False,
                            'type': 'str'
                        },
                        'startip': {
                            'required': False,
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'choices': [
                                'overload',
                                'one-to-one',
                                'fixed-port-range',
                                'port-block-allocation'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'endip': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'num-blocks-per-user': {
                    'required': False,
                    'type': 'int'
                },
                'pba-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'permit-any-host': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'source-endip': {
                    'required': False,
                    'type': 'str'
                },
                'source-startip': {
                    'required': False,
                    'type': 'str'
                },
                'startip': {
                    'required': False,
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'overload',
                        'one-to-one',
                        'fixed-port-range',
                        'port-block-allocation'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool'),
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
