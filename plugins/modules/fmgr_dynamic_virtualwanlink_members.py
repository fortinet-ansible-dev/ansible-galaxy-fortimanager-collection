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
module: fmgr_dynamic_virtualwanlink_members
short_description: no description
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
    dynamic_virtualwanlink_members:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: no description
            cost:
                type: int
                description: no description
            detect-failtime:
                type: int
                description: no description
            detect-http-get:
                type: str
                description: no description
            detect-http-match:
                type: str
                description: no description
            detect-http-port:
                type: int
                description: no description
            detect-interval:
                type: int
                description: no description
            detect-protocol:
                type: str
                description: no description
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
            detect-recoverytime:
                type: int
                description: no description
            detect-server:
                type: str
                description: no description
            detect-timeout:
                type: int
                description: no description
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
                    comment:
                        type: str
                        description: no description
                    cost:
                        type: int
                        description: no description
                    detect-failtime:
                        type: int
                        description: no description
                    detect-http-get:
                        type: str
                        description: no description
                    detect-http-match:
                        type: str
                        description: no description
                    detect-http-port:
                        type: int
                        description: no description
                    detect-interval:
                        type: int
                        description: no description
                    detect-protocol:
                        type: str
                        description: no description
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                    detect-recoverytime:
                        type: int
                        description: no description
                    detect-server:
                        type: str
                        description: no description
                    detect-timeout:
                        type: int
                        description: no description
                    gateway:
                        type: str
                        description: no description
                    gateway6:
                        type: str
                        description: no description
                    ingress-spillover-threshold:
                        type: int
                        description: no description
                    interface:
                        type: str
                        description: no description
                    priority:
                        type: int
                        description: no description
                    source:
                        type: str
                        description: no description
                    source6:
                        type: str
                        description: no description
                    spillover-threshold:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    volume-ratio:
                        type: int
                        description: no description
                    weight:
                        type: int
                        description: no description
            gateway:
                type: str
                description: no description
            gateway6:
                type: str
                description: no description
            ingress-spillover-threshold:
                type: int
                description: no description
            interface:
                type: str
                description: no description
            name:
                type: str
                description: no description
            priority:
                type: int
                description: no description
            source:
                type: str
                description: no description
            source6:
                type: str
                description: no description
            spillover-threshold:
                type: int
                description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            volume-ratio:
                type: int
                description: no description
            weight:
                type: int
                description: no description

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
    - name: no description
      fmgr_dynamic_virtualwanlink_members:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         dynamic_virtualwanlink_members:
            comment: <value of string>
            cost: <value of integer>
            detect-failtime: <value of integer>
            detect-http-get: <value of string>
            detect-http-match: <value of string>
            detect-http-port: <value of integer>
            detect-interval: <value of integer>
            detect-protocol: <value in [ping, tcp-echo, udp-echo, ...]>
            detect-recoverytime: <value of integer>
            detect-server: <value of string>
            detect-timeout: <value of integer>
            dynamic_mapping:
              -
                  _scope:
                    -
                        name: <value of string>
                        vdom: <value of string>
                  comment: <value of string>
                  cost: <value of integer>
                  detect-failtime: <value of integer>
                  detect-http-get: <value of string>
                  detect-http-match: <value of string>
                  detect-http-port: <value of integer>
                  detect-interval: <value of integer>
                  detect-protocol: <value in [ping, tcp-echo, udp-echo, ...]>
                  detect-recoverytime: <value of integer>
                  detect-server: <value of string>
                  detect-timeout: <value of integer>
                  gateway: <value of string>
                  gateway6: <value of string>
                  ingress-spillover-threshold: <value of integer>
                  interface: <value of string>
                  priority: <value of integer>
                  source: <value of string>
                  source6: <value of string>
                  spillover-threshold: <value of integer>
                  status: <value in [disable, enable]>
                  volume-ratio: <value of integer>
                  weight: <value of integer>
            gateway: <value of string>
            gateway6: <value of string>
            ingress-spillover-threshold: <value of integer>
            interface: <value of string>
            name: <value of string>
            priority: <value of integer>
            source: <value of string>
            source6: <value of string>
            spillover-threshold: <value of integer>
            status: <value in [disable, enable]>
            volume-ratio: <value of integer>
            weight: <value of integer>

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
        '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members',
        '/pm/config/global/obj/dynamic/virtual-wan-link/members'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
        '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
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
        'dynamic_virtualwanlink_members': {
            'required': False,
            'type': 'dict',
            'options': {
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'cost': {
                    'required': False,
                    'type': 'int'
                },
                'detect-failtime': {
                    'required': False,
                    'type': 'int'
                },
                'detect-http-get': {
                    'required': False,
                    'type': 'str'
                },
                'detect-http-match': {
                    'required': False,
                    'type': 'str'
                },
                'detect-http-port': {
                    'required': False,
                    'type': 'int'
                },
                'detect-interval': {
                    'required': False,
                    'type': 'int'
                },
                'detect-protocol': {
                    'required': False,
                    'choices': [
                        'ping',
                        'tcp-echo',
                        'udp-echo',
                        'http'
                    ],
                    'type': 'str'
                },
                'detect-recoverytime': {
                    'required': False,
                    'type': 'int'
                },
                'detect-server': {
                    'required': False,
                    'type': 'str'
                },
                'detect-timeout': {
                    'required': False,
                    'type': 'int'
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
                        'comment': {
                            'required': False,
                            'type': 'str'
                        },
                        'cost': {
                            'required': False,
                            'type': 'int'
                        },
                        'detect-failtime': {
                            'required': False,
                            'type': 'int'
                        },
                        'detect-http-get': {
                            'required': False,
                            'type': 'str'
                        },
                        'detect-http-match': {
                            'required': False,
                            'type': 'str'
                        },
                        'detect-http-port': {
                            'required': False,
                            'type': 'int'
                        },
                        'detect-interval': {
                            'required': False,
                            'type': 'int'
                        },
                        'detect-protocol': {
                            'required': False,
                            'choices': [
                                'ping',
                                'tcp-echo',
                                'udp-echo',
                                'http'
                            ],
                            'type': 'str'
                        },
                        'detect-recoverytime': {
                            'required': False,
                            'type': 'int'
                        },
                        'detect-server': {
                            'required': False,
                            'type': 'str'
                        },
                        'detect-timeout': {
                            'required': False,
                            'type': 'int'
                        },
                        'gateway': {
                            'required': False,
                            'type': 'str'
                        },
                        'gateway6': {
                            'required': False,
                            'type': 'str'
                        },
                        'ingress-spillover-threshold': {
                            'required': False,
                            'type': 'int'
                        },
                        'interface': {
                            'required': False,
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'type': 'int'
                        },
                        'source': {
                            'required': False,
                            'type': 'str'
                        },
                        'source6': {
                            'required': False,
                            'type': 'str'
                        },
                        'spillover-threshold': {
                            'required': False,
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'volume-ratio': {
                            'required': False,
                            'type': 'int'
                        },
                        'weight': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'gateway': {
                    'required': False,
                    'type': 'str'
                },
                'gateway6': {
                    'required': False,
                    'type': 'str'
                },
                'ingress-spillover-threshold': {
                    'required': False,
                    'type': 'int'
                },
                'interface': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'priority': {
                    'required': False,
                    'type': 'int'
                },
                'source': {
                    'required': False,
                    'type': 'str'
                },
                'source6': {
                    'required': False,
                    'type': 'str'
                },
                'spillover-threshold': {
                    'required': False,
                    'type': 'int'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'volume-ratio': {
                    'required': False,
                    'type': 'int'
                },
                'weight': {
                    'required': False,
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dynamic_virtualwanlink_members'),
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
