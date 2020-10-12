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
module: fmgr_firewall_sslsshprofile
short_description: Configure SSL/SSH protocol options.
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
    firewall_sslsshprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            caname:
                type: str
                description: 'CA certificate used by SSL Inspection.'
            comment:
                type: str
                description: 'Optional comments.'
            mapi-over-https:
                type: str
                description: 'Enable/disable inspection of MAPI over HTTPS.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'Name.'
            rpc-over-https:
                type: str
                description: 'Enable/disable inspection of RPC over HTTPS.'
                choices:
                    - 'disable'
                    - 'enable'
            server-cert:
                type: str
                description: 'Certificate used by SSL Inspection to replace server certificate.'
            server-cert-mode:
                type: str
                description: 'Re-sign or replace the servers certificate.'
                choices:
                    - 're-sign'
                    - 'replace'
            ssl-anomalies-log:
                type: str
                description: 'Enable/disable logging SSL anomalies.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-exempt:
                description: no description
                type: list
                suboptions:
                    address:
                        type: str
                        description: 'IPv4 address object.'
                    address6:
                        type: str
                        description: 'IPv6 address object.'
                    fortiguard-category:
                        type: str
                        description: 'FortiGuard category ID.'
                    id:
                        type: int
                        description: 'ID number.'
                    regex:
                        type: str
                        description: 'Exempt servers by regular expression.'
                    type:
                        type: str
                        description: 'Type of address object (IPv4 or IPv6) or FortiGuard category.'
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                    wildcard-fqdn:
                        type: str
                        description: 'Exempt servers by wildcard FQDN.'
            ssl-exemptions-log:
                type: str
                description: 'Enable/disable logging SSL exemptions.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server:
                description: no description
                type: list
                suboptions:
                    ftps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the FTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the HTTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        type: int
                        description: 'SSL server ID.'
                    imaps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the IMAPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        type: str
                        description: 'IPv4 address of the SSL server.'
                    pop3s-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the POP3S handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the SMTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl-other-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during an SSL protocol handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            untrusted-caname:
                type: str
                description: 'Untrusted CA certificate used by SSL Inspection.'
            use-ssl-server:
                type: str
                description: 'Enable/disable the use of SSL server table for SSL offloading.'
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                type: str
                description: 'Enable/disable exempting servers by FortiGuard whitelist.'
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
    - name: Configure SSL/SSH protocol options.
      fmgr_firewall_sslsshprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_sslsshprofile:
            caname: <value of string>
            comment: <value of string>
            mapi-over-https: <value in [disable, enable]>
            name: <value of string>
            rpc-over-https: <value in [disable, enable]>
            server-cert: <value of string>
            server-cert-mode: <value in [re-sign, replace]>
            ssl-anomalies-log: <value in [disable, enable]>
            ssl-exempt:
              -
                  address: <value of string>
                  address6: <value of string>
                  fortiguard-category: <value of string>
                  id: <value of integer>
                  regex: <value of string>
                  type: <value in [fortiguard-category, address, address6, ...]>
                  wildcard-fqdn: <value of string>
            ssl-exemptions-log: <value in [disable, enable]>
            ssl-server:
              -
                  ftps-client-cert-request: <value in [bypass, inspect, block]>
                  https-client-cert-request: <value in [bypass, inspect, block]>
                  id: <value of integer>
                  imaps-client-cert-request: <value in [bypass, inspect, block]>
                  ip: <value of string>
                  pop3s-client-cert-request: <value in [bypass, inspect, block]>
                  smtps-client-cert-request: <value in [bypass, inspect, block]>
                  ssl-other-client-cert-request: <value in [bypass, inspect, block]>
            untrusted-caname: <value of string>
            use-ssl-server: <value in [disable, enable]>
            whitelist: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile',
        '/pm/config/global/obj/firewall/ssl-ssh-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
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
        'firewall_sslsshprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                'caname': {
                    'required': False,
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'mapi-over-https': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'rpc-over-https': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'server-cert': {
                    'required': False,
                    'type': 'str'
                },
                'server-cert-mode': {
                    'required': False,
                    'choices': [
                        're-sign',
                        'replace'
                    ],
                    'type': 'str'
                },
                'ssl-anomalies-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-exempt': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'address': {
                            'required': False,
                            'type': 'str'
                        },
                        'address6': {
                            'required': False,
                            'type': 'str'
                        },
                        'fortiguard-category': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'regex': {
                            'required': False,
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'choices': [
                                'fortiguard-category',
                                'address',
                                'address6',
                                'wildcard-fqdn',
                                'regex'
                            ],
                            'type': 'str'
                        },
                        'wildcard-fqdn': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'ssl-exemptions-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-server': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'ftps-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'https-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'imaps-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ip': {
                            'required': False,
                            'type': 'str'
                        },
                        'pop3s-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'smtps-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ssl-other-client-cert-request': {
                            'required': False,
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'untrusted-caname': {
                    'required': False,
                    'type': 'str'
                },
                'use-ssl-server': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'whitelist': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile'),
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
