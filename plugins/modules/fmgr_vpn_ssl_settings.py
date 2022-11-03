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
module: fmgr_vpn_ssl_settings
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
    device:
        description: the parameter (device) in requested url
        type: str
        required: true
    vdom:
        description: the parameter (vdom) in requested url
        type: str
        required: true
    vpn_ssl_settings:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            algorithm:
                type: str
                description: no description
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'medium'
            auth-session-check-source-ip:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auth-timeout:
                type: int
                description: no description
            authentication-rule:
                description: description
                type: list
                suboptions:
                    auth:
                        type: str
                        description: no description
                        choices:
                            - 'any'
                            - 'local'
                            - 'radius'
                            - 'ldap'
                            - 'tacacs+'
                    cipher:
                        type: str
                        description: no description
                        choices:
                            - 'any'
                            - 'high'
                            - 'medium'
                    client-cert:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    portal:
                        type: str
                        description: no description
                    realm:
                        type: str
                        description: no description
                    source-address:
                        type: str
                        description: no description
                    source-address-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    source-address6:
                        type: str
                        description: no description
                    source-address6-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    source-interface:
                        type: str
                        description: no description
                    user-peer:
                        type: str
                        description: no description
                    users:
                        type: str
                        description: no description
            auto-tunnel-static-route:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            banned-cipher:
                description: description
                type: list
                choices:
                 - RSA
                 - DH
                 - DHE
                 - ECDH
                 - ECDHE
                 - DSS
                 - ECDSA
                 - AES
                 - AESGCM
                 - CAMELLIA
                 - 3DES
                 - SHA1
                 - SHA256
                 - SHA384
                 - STATIC
            check-referer:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            default-portal:
                type: str
                description: no description
            deflate-compression-level:
                type: int
                description: no description
            deflate-min-data-size:
                type: int
                description: no description
            dns-server1:
                type: str
                description: no description
            dns-server2:
                type: str
                description: no description
            dns-suffix:
                type: str
                description: no description
            dtls-hello-timeout:
                type: int
                description: no description
            dtls-max-proto-ver:
                type: str
                description: no description
                choices:
                    - 'dtls1-0'
                    - 'dtls1-2'
            dtls-min-proto-ver:
                type: str
                description: no description
                choices:
                    - 'dtls1-0'
                    - 'dtls1-2'
            dtls-tunnel:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            encode-2f-sequence:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            encrypt-and-store-password:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            force-two-factor-auth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            header-x-forwarded-for:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            hsts-include-subdomains:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            http-compression:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            http-only-cookie:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            http-request-body-timeout:
                type: int
                description: no description
            http-request-header-timeout:
                type: int
                description: no description
            https-redirect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            idle-timeout:
                type: int
                description: no description
            ipv6-dns-server1:
                type: str
                description: no description
            ipv6-dns-server2:
                type: str
                description: no description
            ipv6-wins-server1:
                type: str
                description: no description
            ipv6-wins-server2:
                type: str
                description: no description
            login-attempt-limit:
                type: int
                description: no description
            login-block-time:
                type: int
                description: no description
            login-timeout:
                type: int
                description: no description
            port:
                type: int
                description: no description
            port-precedence:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            reqclientcert:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            route-source-interface:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            servercert:
                type: str
                description: no description
            source-address:
                type: str
                description: no description
            source-address-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            source-address6:
                type: str
                description: no description
            source-address6-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            source-interface:
                type: str
                description: no description
            ssl-client-renegotiation:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-insert-empty-fragment:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-max-proto-ver:
                type: str
                description: no description
                choices:
                    - 'tls1-0'
                    - 'tls1-1'
                    - 'tls1-2'
                    - 'tls1-3'
            ssl-min-proto-ver:
                type: str
                description: no description
                choices:
                    - 'tls1-0'
                    - 'tls1-1'
                    - 'tls1-2'
                    - 'tls1-3'
            tlsv1-0:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tlsv1-1:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tlsv1-2:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tlsv1-3:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            transform-backward-slashes:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-connect-without-reauth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-ip-pools:
                type: str
                description: no description
            tunnel-ipv6-pools:
                type: str
                description: no description
            tunnel-user-session-timeout:
                type: int
                description: no description
            unsafe-legacy-renegotiation:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            url-obscuration:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            user-peer:
                type: str
                description: no description
            wins-server1:
                type: str
                description: no description
            wins-server2:
                type: str
                description: no description
            x-content-type-options:
                type: str
                description: no description
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
    - name: no description
      fmgr_vpn_ssl_settings:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         device: <your own value>
         vdom: <your own value>
         vpn_ssl_settings:
            algorithm: <value in [default, high, low, ...]>
            auth-session-check-source-ip: <value in [disable, enable]>
            auth-timeout: <value of integer>
            authentication-rule:
              -
                  auth: <value in [any, local, radius, ...]>
                  cipher: <value in [any, high, medium]>
                  client-cert: <value in [disable, enable]>
                  groups: <value of string>
                  id: <value of integer>
                  portal: <value of string>
                  realm: <value of string>
                  source-address: <value of string>
                  source-address-negate: <value in [disable, enable]>
                  source-address6: <value of string>
                  source-address6-negate: <value in [disable, enable]>
                  source-interface: <value of string>
                  user-peer: <value of string>
                  users: <value of string>
            auto-tunnel-static-route: <value in [disable, enable]>
            banned-cipher:
              - RSA
              - DH
              - DHE
              - ECDH
              - ECDHE
              - DSS
              - ECDSA
              - AES
              - AESGCM
              - CAMELLIA
              - 3DES
              - SHA1
              - SHA256
              - SHA384
              - STATIC
            check-referer: <value in [disable, enable]>
            default-portal: <value of string>
            deflate-compression-level: <value of integer>
            deflate-min-data-size: <value of integer>
            dns-server1: <value of string>
            dns-server2: <value of string>
            dns-suffix: <value of string>
            dtls-hello-timeout: <value of integer>
            dtls-max-proto-ver: <value in [dtls1-0, dtls1-2]>
            dtls-min-proto-ver: <value in [dtls1-0, dtls1-2]>
            dtls-tunnel: <value in [disable, enable]>
            encode-2f-sequence: <value in [disable, enable]>
            encrypt-and-store-password: <value in [disable, enable]>
            force-two-factor-auth: <value in [disable, enable]>
            header-x-forwarded-for: <value in [pass, add, remove]>
            hsts-include-subdomains: <value in [disable, enable]>
            http-compression: <value in [disable, enable]>
            http-only-cookie: <value in [disable, enable]>
            http-request-body-timeout: <value of integer>
            http-request-header-timeout: <value of integer>
            https-redirect: <value in [disable, enable]>
            idle-timeout: <value of integer>
            ipv6-dns-server1: <value of string>
            ipv6-dns-server2: <value of string>
            ipv6-wins-server1: <value of string>
            ipv6-wins-server2: <value of string>
            login-attempt-limit: <value of integer>
            login-block-time: <value of integer>
            login-timeout: <value of integer>
            port: <value of integer>
            port-precedence: <value in [disable, enable]>
            reqclientcert: <value in [disable, enable]>
            route-source-interface: <value in [disable, enable]>
            servercert: <value of string>
            source-address: <value of string>
            source-address-negate: <value in [disable, enable]>
            source-address6: <value of string>
            source-address6-negate: <value in [disable, enable]>
            source-interface: <value of string>
            ssl-client-renegotiation: <value in [disable, enable]>
            ssl-insert-empty-fragment: <value in [disable, enable]>
            ssl-max-proto-ver: <value in [tls1-0, tls1-1, tls1-2, ...]>
            ssl-min-proto-ver: <value in [tls1-0, tls1-1, tls1-2, ...]>
            tlsv1-0: <value in [disable, enable]>
            tlsv1-1: <value in [disable, enable]>
            tlsv1-2: <value in [disable, enable]>
            tlsv1-3: <value in [disable, enable]>
            transform-backward-slashes: <value in [disable, enable]>
            tunnel-connect-without-reauth: <value in [disable, enable]>
            tunnel-ip-pools: <value of string>
            tunnel-ipv6-pools: <value of string>
            tunnel-user-session-timeout: <value of integer>
            unsafe-legacy-renegotiation: <value in [disable, enable]>
            url-obscuration: <value in [disable, enable]>
            user-peer: <value of string>
            wins-server1: <value of string>
            wins-server2: <value of string>
            x-content-type-options: <value in [disable, enable]>

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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings'
    ]

    perobject_jrpc_urls = [
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/{settings}'
    ]

    url_params = ['device', 'vdom']
    module_primary_key = None
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
        'device': {
            'required': True,
            'type': 'str'
        },
        'vdom': {
            'required': True,
            'type': 'str'
        },
        'vpn_ssl_settings': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.4.2': True
            },
            'options': {
                'algorithm': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'default',
                        'high',
                        'low',
                        'medium'
                    ],
                    'type': 'str'
                },
                'auth-session-check-source-ip': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auth-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'authentication-rule': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'list',
                    'options': {
                        'auth': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'any',
                                'local',
                                'radius',
                                'ldap',
                                'tacacs+'
                            ],
                            'type': 'str'
                        },
                        'cipher': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'any',
                                'high',
                                'medium'
                            ],
                            'type': 'str'
                        },
                        'client-cert': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'groups': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'int'
                        },
                        'portal': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'realm': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'source-address': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'source-address-negate': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'source-address6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'source-address6-negate': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'source-interface': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'user-peer': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'users': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'auto-tunnel-static-route': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'banned-cipher': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'list',
                    'choices': [
                        'RSA',
                        'DH',
                        'DHE',
                        'ECDH',
                        'ECDHE',
                        'DSS',
                        'ECDSA',
                        'AES',
                        'AESGCM',
                        'CAMELLIA',
                        '3DES',
                        'SHA1',
                        'SHA256',
                        'SHA384',
                        'STATIC'
                    ]
                },
                'check-referer': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'default-portal': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'deflate-compression-level': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'deflate-min-data-size': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'dns-server1': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'dns-server2': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'dns-suffix': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'dtls-hello-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'dtls-max-proto-ver': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'dtls1-0',
                        'dtls1-2'
                    ],
                    'type': 'str'
                },
                'dtls-min-proto-ver': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'dtls1-0',
                        'dtls1-2'
                    ],
                    'type': 'str'
                },
                'dtls-tunnel': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'encode-2f-sequence': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'encrypt-and-store-password': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'force-two-factor-auth': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'header-x-forwarded-for': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'pass',
                        'add',
                        'remove'
                    ],
                    'type': 'str'
                },
                'hsts-include-subdomains': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'http-compression': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'http-only-cookie': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'http-request-body-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'http-request-header-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'https-redirect': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'idle-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'ipv6-dns-server1': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'ipv6-dns-server2': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'ipv6-wins-server1': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'ipv6-wins-server2': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'login-attempt-limit': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'login-block-time': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'login-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'port': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'port-precedence': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'reqclientcert': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'route-source-interface': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'servercert': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'source-address': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'source-address-negate': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'source-address6': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'source-address6-negate': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'source-interface': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'ssl-client-renegotiation': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-insert-empty-fragment': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-max-proto-ver': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'tls1-0',
                        'tls1-1',
                        'tls1-2',
                        'tls1-3'
                    ],
                    'type': 'str'
                },
                'ssl-min-proto-ver': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'tls1-0',
                        'tls1-1',
                        'tls1-2',
                        'tls1-3'
                    ],
                    'type': 'str'
                },
                'tlsv1-0': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tlsv1-1': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tlsv1-2': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tlsv1-3': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'transform-backward-slashes': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-connect-without-reauth': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-ip-pools': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'tunnel-ipv6-pools': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'tunnel-user-session-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'unsafe-legacy-renegotiation': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'url-obscuration': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user-peer': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'wins-server1': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'wins-server2': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'x-content-type-options': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ssl_settings'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
