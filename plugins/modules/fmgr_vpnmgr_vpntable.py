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
module: fmgr_vpnmgr_vpntable
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
    vpnmgr_vpntable:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            authmethod:
                type: str
                description: no description
                choices:
                    - 'psk'
                    - 'rsa-signature'
                    - 'signature'
            auto-zone-policy:
                type: str
                default: 'enable'
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            certificate:
                type: str
                description: no description
            description:
                type: str
                description: no description
            dpd:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'on-idle'
                    - 'on-demand'
            dpd-retrycount:
                type: int
                description: no description
            dpd-retryinterval:
                description: no description
                type: int
            fcc-enforcement:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            hub2spoke-zone:
                type: str
                description: no description
            ike-version:
                type: str
                description: no description
                choices:
                    - '1'
                    - '2'
            ike1dhgroup:
                description: no description
                type: list
                choices:
                 - 1
                 - 2
                 - 5
                 - 14
                 - 15
                 - 16
                 - 17
                 - 18
                 - 19
                 - 20
                 - 21
                 - 27
                 - 28
                 - 29
                 - 30
                 - 31
                 - 32
            ike1dpd:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ike1keylifesec:
                type: int
                description: no description
            ike1localid:
                type: str
                description: no description
            ike1mode:
                type: str
                description: no description
                choices:
                    - 'main'
                    - 'aggressive'
            ike1natkeepalive:
                type: int
                description: no description
            ike1nattraversal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'forced'
            ike1proposal:
                type: str
                description: no description
                choices:
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
                    - 'aes128gcm-prfsha1'
                    - 'aes128gcm-prfsha256'
                    - 'aes128gcm-prfsha384'
                    - 'aes128gcm-prfsha512'
                    - 'aes256gcm-prfsha1'
                    - 'aes256gcm-prfsha256'
                    - 'aes256gcm-prfsha384'
                    - 'aes256gcm-prfsha512'
                    - 'chacha20poly1305-prfsha1'
                    - 'chacha20poly1305-prfsha256'
                    - 'chacha20poly1305-prfsha384'
                    - 'chacha20poly1305-prfsha512'
            ike2autonego:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ike2dhgroup:
                description: no description
                type: list
                choices:
                 - 1
                 - 2
                 - 5
                 - 14
                 - 15
                 - 16
                 - 17
                 - 18
                 - 19
                 - 20
                 - 21
                 - 27
                 - 28
                 - 29
                 - 30
                 - 31
                 - 32
            ike2keepalive:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ike2keylifekbs:
                type: int
                description: no description
            ike2keylifesec:
                type: int
                description: no description
            ike2keylifetype:
                type: str
                description: no description
                choices:
                    - 'seconds'
                    - 'kbs'
                    - 'both'
            ike2proposal:
                type: str
                description: no description
                choices:
                    - 'null-md5'
                    - 'null-sha1'
                    - 'des-null'
                    - '3des-null'
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'aes128-null'
                    - 'aes192-null'
                    - 'aes256-null'
                    - 'null-sha256'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'null-sha384'
                    - 'null-sha512'
                    - 'aria128-null'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-null'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-null'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-null'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
                    - 'aes128gcm'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
            inter-vdom:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            intf-mode:
                type: str
                description: no description
                choices:
                    - 'off'
                    - 'on'
            localid-type:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - 'fqdn'
                    - 'user-fqdn'
                    - 'keyid'
                    - 'address'
                    - 'asn1dn'
            name:
                type: str
                description: no description
            negotiate-timeout:
                type: int
                default: 30
                description: no description
            npu-offload:
                type: str
                default: 'enable'
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            pfs:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            psk-auto-generate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            psksecret:
                description: no description
                type: str
            replay:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rsa-certificate:
                type: str
                description: no description
            spoke2hub-zone:
                type: str
                description: no description
            topology:
                type: str
                description: no description
                choices:
                    - 'meshed'
                    - 'star'
                    - 'dialup'
            vpn-zone:
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
      fmgr_vpnmgr_vpntable:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         vpnmgr_vpntable:
            authmethod: <value in [psk, rsa-signature, signature]>
            auto-zone-policy: <value in [disable, enable]>
            certificate: <value of string>
            description: <value of string>
            dpd: <value in [disable, enable, on-idle, ...]>
            dpd-retrycount: <value of integer>
            dpd-retryinterval: <value of integer>
            fcc-enforcement: <value in [disable, enable]>
            hub2spoke-zone: <value of string>
            ike-version: <value in [1, 2]>
            ike1dhgroup:
              - 1
              - 2
              - 5
              - 14
              - 15
              - 16
              - 17
              - 18
              - 19
              - 20
              - 21
              - 27
              - 28
              - 29
              - 30
              - 31
              - 32
            ike1dpd: <value in [disable, enable]>
            ike1keylifesec: <value of integer>
            ike1localid: <value of string>
            ike1mode: <value in [main, aggressive]>
            ike1natkeepalive: <value of integer>
            ike1nattraversal: <value in [disable, enable, forced]>
            ike1proposal: <value in [des-md5, des-sha1, 3des-md5, ...]>
            ike2autonego: <value in [disable, enable]>
            ike2dhgroup:
              - 1
              - 2
              - 5
              - 14
              - 15
              - 16
              - 17
              - 18
              - 19
              - 20
              - 21
              - 27
              - 28
              - 29
              - 30
              - 31
              - 32
            ike2keepalive: <value in [disable, enable]>
            ike2keylifekbs: <value of integer>
            ike2keylifesec: <value of integer>
            ike2keylifetype: <value in [seconds, kbs, both]>
            ike2proposal: <value in [null-md5, null-sha1, des-null, ...]>
            inter-vdom: <value in [disable, enable]>
            intf-mode: <value in [off, on]>
            localid-type: <value in [auto, fqdn, user-fqdn, ...]>
            name: <value of string>
            negotiate-timeout: <value of integer>
            npu-offload: <value in [disable, enable]>
            pfs: <value in [disable, enable]>
            psk-auto-generate: <value in [disable, enable]>
            psksecret: <value of string>
            replay: <value in [disable, enable]>
            rsa-certificate: <value of string>
            spoke2hub-zone: <value of string>
            topology: <value in [meshed, star, dialup]>
            vpn-zone: <value of string>

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
        '/pm/config/adom/{adom}/obj/vpnmgr/vpntable',
        '/pm/config/global/obj/vpnmgr/vpntable'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
        '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
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
        'vpnmgr_vpntable': {
            'required': False,
            'type': 'dict',
            'options': {
                'authmethod': {
                    'required': False,
                    'choices': [
                        'psk',
                        'rsa-signature',
                        'signature'
                    ],
                    'type': 'str'
                },
                'auto-zone-policy': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'certificate': {
                    'required': False,
                    'type': 'str'
                },
                'description': {
                    'required': False,
                    'type': 'str'
                },
                'dpd': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'on-idle',
                        'on-demand'
                    ],
                    'type': 'str'
                },
                'dpd-retrycount': {
                    'required': False,
                    'type': 'int'
                },
                'dpd-retryinterval': {
                    'required': False,
                    'type': 'int'
                },
                'fcc-enforcement': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'hub2spoke-zone': {
                    'required': False,
                    'type': 'str'
                },
                'ike-version': {
                    'required': False,
                    'choices': [
                        '1',
                        '2'
                    ],
                    'type': 'str'
                },
                'ike1dhgroup': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        '1',
                        '2',
                        '5',
                        '14',
                        '15',
                        '16',
                        '17',
                        '18',
                        '19',
                        '20',
                        '21',
                        '27',
                        '28',
                        '29',
                        '30',
                        '31',
                        '32'
                    ]
                },
                'ike1dpd': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ike1keylifesec': {
                    'required': False,
                    'type': 'int'
                },
                'ike1localid': {
                    'required': False,
                    'type': 'str'
                },
                'ike1mode': {
                    'required': False,
                    'choices': [
                        'main',
                        'aggressive'
                    ],
                    'type': 'str'
                },
                'ike1natkeepalive': {
                    'required': False,
                    'type': 'int'
                },
                'ike1nattraversal': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'forced'
                    ],
                    'type': 'str'
                },
                'ike1proposal': {
                    'required': False,
                    'choices': [
                        'des-md5',
                        'des-sha1',
                        '3des-md5',
                        '3des-sha1',
                        'aes128-md5',
                        'aes128-sha1',
                        'aes192-md5',
                        'aes192-sha1',
                        'aes256-md5',
                        'aes256-sha1',
                        'des-sha256',
                        '3des-sha256',
                        'aes128-sha256',
                        'aes192-sha256',
                        'aes256-sha256',
                        'des-sha384',
                        'des-sha512',
                        '3des-sha384',
                        '3des-sha512',
                        'aes128-sha384',
                        'aes128-sha512',
                        'aes192-sha384',
                        'aes192-sha512',
                        'aes256-sha384',
                        'aes256-sha512',
                        'aria128-md5',
                        'aria128-sha1',
                        'aria128-sha256',
                        'aria128-sha384',
                        'aria128-sha512',
                        'aria192-md5',
                        'aria192-sha1',
                        'aria192-sha256',
                        'aria192-sha384',
                        'aria192-sha512',
                        'aria256-md5',
                        'aria256-sha1',
                        'aria256-sha256',
                        'aria256-sha384',
                        'aria256-sha512',
                        'seed-md5',
                        'seed-sha1',
                        'seed-sha256',
                        'seed-sha384',
                        'seed-sha512',
                        'aes128gcm-prfsha1',
                        'aes128gcm-prfsha256',
                        'aes128gcm-prfsha384',
                        'aes128gcm-prfsha512',
                        'aes256gcm-prfsha1',
                        'aes256gcm-prfsha256',
                        'aes256gcm-prfsha384',
                        'aes256gcm-prfsha512',
                        'chacha20poly1305-prfsha1',
                        'chacha20poly1305-prfsha256',
                        'chacha20poly1305-prfsha384',
                        'chacha20poly1305-prfsha512'
                    ],
                    'type': 'str'
                },
                'ike2autonego': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ike2dhgroup': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        '1',
                        '2',
                        '5',
                        '14',
                        '15',
                        '16',
                        '17',
                        '18',
                        '19',
                        '20',
                        '21',
                        '27',
                        '28',
                        '29',
                        '30',
                        '31',
                        '32'
                    ]
                },
                'ike2keepalive': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ike2keylifekbs': {
                    'required': False,
                    'type': 'int'
                },
                'ike2keylifesec': {
                    'required': False,
                    'type': 'int'
                },
                'ike2keylifetype': {
                    'required': False,
                    'choices': [
                        'seconds',
                        'kbs',
                        'both'
                    ],
                    'type': 'str'
                },
                'ike2proposal': {
                    'required': False,
                    'choices': [
                        'null-md5',
                        'null-sha1',
                        'des-null',
                        '3des-null',
                        'des-md5',
                        'des-sha1',
                        '3des-md5',
                        '3des-sha1',
                        'aes128-md5',
                        'aes128-sha1',
                        'aes192-md5',
                        'aes192-sha1',
                        'aes256-md5',
                        'aes256-sha1',
                        'aes128-null',
                        'aes192-null',
                        'aes256-null',
                        'null-sha256',
                        'des-sha256',
                        '3des-sha256',
                        'aes128-sha256',
                        'aes192-sha256',
                        'aes256-sha256',
                        'des-sha384',
                        'des-sha512',
                        '3des-sha384',
                        '3des-sha512',
                        'aes128-sha384',
                        'aes128-sha512',
                        'aes192-sha384',
                        'aes192-sha512',
                        'aes256-sha384',
                        'aes256-sha512',
                        'null-sha384',
                        'null-sha512',
                        'aria128-null',
                        'aria128-md5',
                        'aria128-sha1',
                        'aria128-sha256',
                        'aria128-sha384',
                        'aria128-sha512',
                        'aria192-null',
                        'aria192-md5',
                        'aria192-sha1',
                        'aria192-sha256',
                        'aria192-sha384',
                        'aria192-sha512',
                        'aria256-null',
                        'aria256-md5',
                        'aria256-sha1',
                        'aria256-sha256',
                        'aria256-sha384',
                        'aria256-sha512',
                        'seed-null',
                        'seed-md5',
                        'seed-sha1',
                        'seed-sha256',
                        'seed-sha384',
                        'seed-sha512',
                        'aes128gcm',
                        'aes256gcm',
                        'chacha20poly1305'
                    ],
                    'type': 'str'
                },
                'inter-vdom': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'intf-mode': {
                    'required': False,
                    'choices': [
                        'off',
                        'on'
                    ],
                    'type': 'str'
                },
                'localid-type': {
                    'required': False,
                    'choices': [
                        'auto',
                        'fqdn',
                        'user-fqdn',
                        'keyid',
                        'address',
                        'asn1dn'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'negotiate-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'npu-offload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'pfs': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'psk-auto-generate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'psksecret': {
                    'required': False,
                    'type': 'str'
                },
                'replay': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rsa-certificate': {
                    'required': False,
                    'type': 'str'
                },
                'spoke2hub-zone': {
                    'required': False,
                    'type': 'str'
                },
                'topology': {
                    'required': False,
                    'choices': [
                        'meshed',
                        'star',
                        'dialup'
                    ],
                    'type': 'str'
                },
                'vpn-zone': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnmgr_vpntable'),
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
