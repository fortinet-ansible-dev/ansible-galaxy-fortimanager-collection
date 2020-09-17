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
module: fmgr_pkg_header_policy_identitybasedpolicy
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    policy:
        description: the parameter (policy) in requested url
        type: str
        required: true
    pkg_header_policy_identitybasedpolicy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'accept'
            application-charts:
                description: no description
                type: list
                choices:
                 - top10-app
                 - top10-p2p-user
                 - top10-media-user
            application-list:
                type: str
                description: no description
            av-profile:
                type: str
                description: no description
            capture-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            deep-inspection-options:
                type: str
                description: no description
            devices:
                type: str
                description: no description
            dlp-sensor:
                type: str
                description: no description
            dstaddr:
                type: str
                description: no description
            dstaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-compliance:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: str
                description: no description
            icap-profile:
                type: str
                description: no description
            id:
                type: int
                description: no description
            ips-sensor:
                type: str
                description: no description
            logtraffic:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic-app:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic-start:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: str
                description: no description
            per-ip-shaper:
                type: str
                description: no description
            profile-group:
                type: str
                description: no description
            profile-protocol-options:
                type: str
                description: no description
            profile-type:
                type: str
                description: no description
                choices:
                    - 'single'
                    - 'group'
            replacemsg-group:
                type: str
                description: no description
            schedule:
                type: str
                description: no description
            send-deny-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: str
                description: no description
            service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter-profile:
                type: str
                description: no description
            sslvpn-portal:
                type: str
                description: no description
            sslvpn-realm:
                type: str
                description: no description
            traffic-shaper:
                type: str
                description: no description
            traffic-shaper-reverse:
                type: str
                description: no description
            users:
                type: str
                description: no description
            utm-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            voip-profile:
                type: str
                description: no description
            webfilter-profile:
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
      fmgr_pkg_header_policy_identitybasedpolicy:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         pkg: <your own value>
         policy: <your own value>
         state: <value in [present, absent]>
         pkg_header_policy_identitybasedpolicy:
            action: <value in [deny, accept]>
            application-charts:
              - top10-app
              - top10-p2p-user
              - top10-media-user
            application-list: <value of string>
            av-profile: <value of string>
            capture-packet: <value in [disable, enable]>
            deep-inspection-options: <value of string>
            devices: <value of string>
            dlp-sensor: <value of string>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            endpoint-compliance: <value in [disable, enable]>
            groups: <value of string>
            icap-profile: <value of string>
            id: <value of integer>
            ips-sensor: <value of string>
            logtraffic: <value in [disable, enable, all, ...]>
            logtraffic-app: <value in [disable, enable]>
            logtraffic-start: <value in [disable, enable]>
            mms-profile: <value of string>
            per-ip-shaper: <value of string>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            replacemsg-group: <value of string>
            schedule: <value of string>
            send-deny-packet: <value in [disable, enable]>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            spamfilter-profile: <value of string>
            sslvpn-portal: <value of string>
            sslvpn-realm: <value of string>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            users: <value of string>
            utm-status: <value in [disable, enable]>
            voip-profile: <value of string>
            webfilter-profile: <value of string>

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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.NAPI import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.NAPI import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.NAPI import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
    ]

    url_params = ['pkg', 'policy']
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'policy': {
            'required': True,
            'type': 'str'
        },
        'pkg_header_policy_identitybasedpolicy': {
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
                'application-charts': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'top10-app',
                        'top10-p2p-user',
                        'top10-media-user'
                    ]
                },
                'application-list': {
                    'required': False,
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'type': 'str'
                },
                'capture-packet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'deep-inspection-options': {
                    'required': False,
                    'type': 'str'
                },
                'devices': {
                    'required': False,
                    'type': 'str'
                },
                'dlp-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'endpoint-compliance': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'type': 'str'
                },
                'icap-profile': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'ips-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'logtraffic-app': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'logtraffic-start': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-profile': {
                    'required': False,
                    'type': 'str'
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'profile-group': {
                    'required': False,
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'type': 'str'
                },
                'send-deny-packet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'type': 'str'
                },
                'service-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spamfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'sslvpn-portal': {
                    'required': False,
                    'type': 'str'
                },
                'sslvpn-realm': {
                    'required': False,
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
                'users': {
                    'required': False,
                    'type': 'str'
                },
                'utm-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'voip-profile': {
                    'required': False,
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_header_policy_identitybasedpolicy'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
