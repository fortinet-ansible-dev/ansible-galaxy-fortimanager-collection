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
module: fmgr_router_routemap
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    router_routemap:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: no description
            name:
                type: str
                description: no description
            rule:
                description: description
                type: list
                suboptions:
                    action:
                        type: str
                        description: no description
                        choices:
                            - 'permit'
                            - 'deny'
                    id:
                        type: int
                        description: no description
                    match-as-path:
                        type: str
                        description: no description
                    match-community:
                        type: str
                        description: no description
                    match-community-exact:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    match-flags:
                        type: int
                        description: no description
                    match-interface:
                        type: str
                        description: no description
                    match-ip-address:
                        type: str
                        description: no description
                    match-ip-nexthop:
                        type: str
                        description: no description
                    match-ip6-address:
                        type: str
                        description: no description
                    match-ip6-nexthop:
                        type: str
                        description: no description
                    match-metric:
                        type: str
                        description: no description
                    match-origin:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    match-route-type:
                        type: str
                        description: no description
                        choices:
                            - '1'
                            - '2'
                            - 'none'
                            - 'external-type1'
                            - 'external-type2'
                    match-tag:
                        type: str
                        description: no description
                    match-vrf:
                        type: int
                        description: no description
                    set-aggregator-as:
                        type: int
                        description: no description
                    set-aggregator-ip:
                        type: str
                        description: no description
                    set-aspath:
                        description: description
                        type: str
                    set-aspath-action:
                        type: str
                        description: no description
                        choices:
                            - 'prepend'
                            - 'replace'
                    set-atomic-aggregate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    set-community:
                        description: description
                        type: str
                    set-community-additive:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    set-community-delete:
                        type: str
                        description: no description
                    set-dampening-max-suppress:
                        type: int
                        description: no description
                    set-dampening-reachability-half-life:
                        type: int
                        description: no description
                    set-dampening-reuse:
                        type: int
                        description: no description
                    set-dampening-suppress:
                        type: int
                        description: no description
                    set-dampening-unreachability-half-life:
                        type: int
                        description: no description
                    set-extcommunity-rt:
                        description: description
                        type: str
                    set-extcommunity-soo:
                        description: description
                        type: str
                    set-flags:
                        type: int
                        description: no description
                    set-ip-nexthop:
                        type: str
                        description: no description
                    set-ip6-nexthop:
                        type: str
                        description: no description
                    set-ip6-nexthop-local:
                        type: str
                        description: no description
                    set-local-preference:
                        type: str
                        description: no description
                    set-metric:
                        type: str
                        description: no description
                    set-metric-type:
                        type: str
                        description: no description
                        choices:
                            - '1'
                            - '2'
                            - 'none'
                            - 'external-type1'
                            - 'external-type2'
                    set-origin:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    set-originator-id:
                        type: str
                        description: no description
                    set-priority:
                        type: int
                        description: no description
                    set-route-tag:
                        type: str
                        description: no description
                    set-tag:
                        type: str
                        description: no description
                    set-weight:
                        type: str
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
      fmgr_router_routemap:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         router_routemap:
            comments: <value of string>
            name: <value of string>
            rule:
              -
                  action: <value in [permit, deny]>
                  id: <value of integer>
                  match-as-path: <value of string>
                  match-community: <value of string>
                  match-community-exact: <value in [disable, enable]>
                  match-flags: <value of integer>
                  match-interface: <value of string>
                  match-ip-address: <value of string>
                  match-ip-nexthop: <value of string>
                  match-ip6-address: <value of string>
                  match-ip6-nexthop: <value of string>
                  match-metric: <value of string>
                  match-origin: <value in [none, egp, igp, ...]>
                  match-route-type: <value in [1, 2, none, ...]>
                  match-tag: <value of string>
                  match-vrf: <value of integer>
                  set-aggregator-as: <value of integer>
                  set-aggregator-ip: <value of string>
                  set-aspath: <value of string>
                  set-aspath-action: <value in [prepend, replace]>
                  set-atomic-aggregate: <value in [disable, enable]>
                  set-community: <value of string>
                  set-community-additive: <value in [disable, enable]>
                  set-community-delete: <value of string>
                  set-dampening-max-suppress: <value of integer>
                  set-dampening-reachability-half-life: <value of integer>
                  set-dampening-reuse: <value of integer>
                  set-dampening-suppress: <value of integer>
                  set-dampening-unreachability-half-life: <value of integer>
                  set-extcommunity-rt: <value of string>
                  set-extcommunity-soo: <value of string>
                  set-flags: <value of integer>
                  set-ip-nexthop: <value of string>
                  set-ip6-nexthop: <value of string>
                  set-ip6-nexthop-local: <value of string>
                  set-local-preference: <value of string>
                  set-metric: <value of string>
                  set-metric-type: <value in [1, 2, none, ...]>
                  set-origin: <value in [none, egp, igp, ...]>
                  set-originator-id: <value of string>
                  set-priority: <value of integer>
                  set-route-tag: <value of string>
                  set-tag: <value of string>
                  set-weight: <value of string>

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
        '/pm/config/global/obj/router/route-map',
        '/pm/config/adom/{adom}/obj/router/route-map'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/router/route-map/{route-map}',
        '/pm/config/adom/{adom}/obj/router/route-map/{route-map}'
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
        'router_routemap': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                'comments': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'rule': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'permit',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'match-as-path': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-community': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-community-exact': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'match-flags': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'match-interface': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-ip-address': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-ip-nexthop': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-ip6-address': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-ip6-nexthop': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-metric': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-origin': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'none',
                                'egp',
                                'igp',
                                'incomplete'
                            ],
                            'type': 'str'
                        },
                        'match-route-type': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                '1',
                                '2',
                                'none',
                                'external-type1',
                                'external-type2'
                            ],
                            'type': 'str'
                        },
                        'match-tag': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'match-vrf': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-aggregator-as': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-aggregator-ip': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-aspath': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-aspath-action': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'prepend',
                                'replace'
                            ],
                            'type': 'str'
                        },
                        'set-atomic-aggregate': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'set-community': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-community-additive': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'set-community-delete': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-dampening-max-suppress': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-dampening-reachability-half-life': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-dampening-reuse': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-dampening-suppress': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-dampening-unreachability-half-life': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-extcommunity-rt': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-extcommunity-soo': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-flags': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-ip-nexthop': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-ip6-nexthop': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-ip6-nexthop-local': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-local-preference': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-metric': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-metric-type': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                '1',
                                '2',
                                'none',
                                'external-type1',
                                'external-type2'
                            ],
                            'type': 'str'
                        },
                        'set-origin': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'none',
                                'egp',
                                'igp',
                                'incomplete'
                            ],
                            'type': 'str'
                        },
                        'set-originator-id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-priority': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'set-route-tag': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-tag': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'set-weight': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_routemap'),
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
