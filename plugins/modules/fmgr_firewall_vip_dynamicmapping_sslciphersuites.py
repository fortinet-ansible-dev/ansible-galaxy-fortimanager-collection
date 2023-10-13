#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
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
module: fmgr_firewall_vip_dynamicmapping_sslciphersuites
short_description: SSL/TLS cipher suites acceptable from a client, ordered by priority.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
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
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    vip:
        description: the parameter (vip) in requested url
        type: str
        required: true
    dynamic_mapping:
        description: the parameter (dynamic_mapping) in requested url
        type: str
        required: true
    firewall_vip_dynamicmapping_sslciphersuites:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            cipher:
                type: str
                description: no description
                choices:
                    - 'TLS-RSA-WITH-RC4-128-MD5'
                    - 'TLS-RSA-WITH-RC4-128-SHA'
                    - 'TLS-RSA-WITH-DES-CBC-SHA'
                    - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                    - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                    - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                    - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                    - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                    - 'TLS-RSA-WITH-SEED-CBC-SHA'
                    - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                    - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                    - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                    - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                    - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                    - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                    - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                    - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                    - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                    - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                    - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                    - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                    - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                    - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                    - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                    - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                    - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                    - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                    - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                    - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                    - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                    - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                    - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                    - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                    - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                    - 'TLS-AES-128-GCM-SHA256'
                    - 'TLS-AES-256-GCM-SHA384'
                    - 'TLS-CHACHA20-POLY1305-SHA256'
                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
            id:
                type: int
                description: no description
                required: true
            versions:
                type: list
                elements: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            priority:
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
    - name: SSL/TLS cipher suites acceptable from a client, ordered by priority.
      fmgr_firewall_vip_dynamicmapping_sslciphersuites:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        adom: <your own value>
        vip: <your own value>
        dynamic_mapping: <your own value>
        state: <value in [present, absent]>
        firewall_vip_dynamicmapping_sslciphersuites:
          cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          id: <integer>
          versions:
            - ssl-3.0
            - tls-1.0
            - tls-1.1
            - tls-1.2
            - tls-1.3
          priority: <integer>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites',
        '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
        '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
    ]

    url_params = ['adom', 'vip', 'dynamic_mapping']
    module_primary_key = 'id'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
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
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'vip': {
            'required': True,
            'type': 'str'
        },
        'dynamic_mapping': {
            'required': True,
            'type': 'str'
        },
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.2.11': True,
                '6.2.12': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '6.4.12': True,
                '6.4.13': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.0.8': True,
                '7.0.9': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.2.3': True,
                '7.2.4': True,
                '7.4.0': True
            },
            'options': {
                'cipher': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': False
                    },
                    'choices': [
                        'TLS-RSA-WITH-RC4-128-MD5',
                        'TLS-RSA-WITH-RC4-128-SHA',
                        'TLS-RSA-WITH-DES-CBC-SHA',
                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                        'TLS-RSA-WITH-AES-128-CBC-SHA',
                        'TLS-RSA-WITH-AES-256-CBC-SHA',
                        'TLS-RSA-WITH-AES-128-CBC-SHA256',
                        'TLS-RSA-WITH-AES-256-CBC-SHA256',
                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                        'TLS-RSA-WITH-SEED-CBC-SHA',
                        'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                        'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                        'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                        'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                        'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                        'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                        'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                        'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                        'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                        'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                        'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                        'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                        'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                        'TLS-RSA-WITH-AES-128-GCM-SHA256',
                        'TLS-RSA-WITH-AES-256-GCM-SHA384',
                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                        'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                        'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                        'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                        'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                        'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                        'TLS-AES-128-GCM-SHA256',
                        'TLS-AES-256-GCM-SHA384',
                        'TLS-CHACHA20-POLY1305-SHA256',
                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                    ],
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': False
                    },
                    'type': 'int'
                },
                'versions': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': False
                    },
                    'type': 'list',
                    'choices': [
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'tls-1.3'
                    ],
                    'elements': 'str'
                },
                'priority': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': False
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip_dynamicmapping_sslciphersuites'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
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
