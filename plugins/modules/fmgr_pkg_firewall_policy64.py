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
module: fmgr_pkg_firewall_policy64
short_description: Configure IPv6 to IPv4 policies.
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
    pkg_firewall_policy64:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: 'Policy action.'
                choices:
                    - 'deny'
                    - 'accept'
            comments:
                type: str
                description: 'Comment.'
            dstaddr:
                type: str
                description: 'Destination address name.'
            dstintf:
                type: str
                description: 'Destination interface name.'
            fixedport:
                type: str
                description: 'Enable/disable policy fixed port.'
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: 'Enable/disable policy64 IP pool.'
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: 'Enable/disable policy log traffic.'
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: 'Per-IP traffic shaper.'
            permit-any-host:
                type: str
                description: 'Enable/disable permit any host in.'
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: 'Policy ID.'
            poolname:
                type: str
                description: 'Policy IP pool names.'
            schedule:
                type: str
                description: 'Schedule name.'
            service:
                type: str
                description: 'Service name.'
            srcaddr:
                type: str
                description: 'Source address name.'
            srcintf:
                type: str
                description: 'Source interface name.'
            status:
                type: str
                description: 'Enable/disable policy status.'
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: 'Applied object tags.'
            tcp-mss-receiver:
                type: int
                description: 'TCP MSS value of receiver.'
            tcp-mss-sender:
                type: int
                description: 'TCP MSS value of sender.'
            traffic-shaper:
                type: str
                description: 'Traffic shaper.'
            traffic-shaper-reverse:
                type: str
                description: 'Reverse traffic shaper.'
            uuid:
                type: str
                description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'

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
    - name: Configure IPv6 to IPv4 policies.
      fmgr_pkg_firewall_policy64:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pkg: <your own value>
         state: <value in [present, absent]>
         pkg_firewall_policy64:
            action: <value in [deny, accept]>
            comments: <value of string>
            dstaddr: <value of string>
            dstintf: <value of string>
            fixedport: <value in [disable, enable]>
            ippool: <value in [disable, enable]>
            logtraffic: <value in [disable, enable]>
            per-ip-shaper: <value of string>
            permit-any-host: <value in [disable, enable]>
            policyid: <value of integer>
            poolname: <value of string>
            schedule: <value of string>
            service: <value of string>
            srcaddr: <value of string>
            srcintf: <value of string>
            status: <value in [disable, enable]>
            tags: <value of string>
            tcp-mss-receiver: <value of integer>
            tcp-mss-sender: <value of integer>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            uuid: <value of string>

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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
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
        'pkg_firewall_policy64': {
            'required': False,
            'type': 'dict',
            'options': {
                'action': {
                    'required': False,
                    'choices': [
                        'deny',
                        'accept'
                    ],
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'type': 'str'
                },
                'fixedport': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ippool': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'permit-any-host': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'policyid': {
                    'required': True,
                    'type': 'int'
                },
                'poolname': {
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
                'srcintf': {
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
                'tags': {
                    'required': False,
                    'type': 'str'
                },
                'tcp-mss-receiver': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-mss-sender': {
                    'required': False,
                    'type': 'int'
                },
                'traffic-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'traffic-shaper-reverse': {
                    'required': False,
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy64'),
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
