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
module: fmgr_pkg_firewall_shapingpolicy
short_description: Configure shaping policies.
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_firewall_shapingpolicy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            app-category:
                type: str
                description: 'IDs of one or more application categories that this shaper applies application control traffic shaping to.'
            application:
                description: no description
                type: int
            dstaddr:
                type: str
                description: 'IPv4 destination address and address group names.'
            dstaddr6:
                type: str
                description: 'IPv6 destination address and address group names.'
            dstintf:
                type: str
                description: 'One or more outgoing (egress) interfaces.'
            groups:
                type: str
                description: 'Apply this traffic shaping policy to user groups that have authenticated with the FortiGate.'
            id:
                type: int
                description: 'Shaping policy ID.'
            ip-version:
                type: str
                description: 'Apply this traffic shaping policy to IPv4 or IPv6 traffic.'
                choices:
                    - '4'
                    - '6'
            per-ip-shaper:
                type: str
                description: 'Per-IP traffic shaper to apply with this policy.'
            schedule:
                type: str
                description: 'Schedule name.'
            service:
                type: str
                description: 'Service and service group names.'
            srcaddr:
                type: str
                description: 'IPv4 source address and address group names.'
            srcaddr6:
                type: str
                description: 'IPv6 source address and address group names.'
            status:
                type: str
                description: 'Enable/disable this traffic shaping policy.'
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: 'Traffic shaper to apply to traffic forwarded by the firewall policy.'
            traffic-shaper-reverse:
                type: str
                description: 'Traffic shaper to apply to response traffic received by the firewall policy.'
            url-category:
                type: str
                description: 'IDs of one or more FortiGuard Web Filtering categories that this shaper applies traffic shaping to.'
            users:
                type: str
                description: 'Apply this traffic shaping policy to individual users that have authenticated with the FortiGate.'

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
    - name: Configure shaping policies.
      fmgr_pkg_firewall_shapingpolicy:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pkg: <your own value>
         state: <value in [present, absent]>
         pkg_firewall_shapingpolicy:
            app-category: <value of string>
            application: <value of integer>
            dstaddr: <value of string>
            dstaddr6: <value of string>
            dstintf: <value of string>
            groups: <value of string>
            id: <value of integer>
            ip-version: <value in [4, 6]>
            per-ip-shaper: <value of string>
            schedule: <value of string>
            service: <value of string>
            srcaddr: <value of string>
            srcaddr6: <value of string>
            status: <value in [disable, enable]>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            url-category: <value of string>
            users: <value of string>

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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
    ]

    url_params = ['adom', 'pkg']
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_firewall_shapingpolicy': {
            'required': False,
            'type': 'dict',
            'options': {
                'app-category': {
                    'required': False,
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'type': 'int'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr6': {
                    'required': False,
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'ip-version': {
                    'required': False,
                    'choices': [
                        '4',
                        '6'
                    ],
                    'type': 'str'
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr6': {
                    'required': False,
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
                'traffic-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'traffic-shaper-reverse': {
                    'required': False,
                    'type': 'str'
                },
                'url-category': {
                    'required': False,
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_shapingpolicy'),
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
