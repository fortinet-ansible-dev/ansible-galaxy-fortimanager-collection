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
module: fmgr_firewall_sslsshprofile_dot
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
    ssl-ssh-profile:
        description: the parameter (ssl-ssh-profile) in requested url
        type: str
        required: true
    firewall_sslsshprofile_dot:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            cert-validation-failure:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            cert-validation-timeout:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            client-certificate:
                type: str
                description: no description
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            expired-server-cert:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            proxy-after-tcp-handshake:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            revoked-server-cert:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            sni-server-cert-check:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'strict'
                    - 'disable'
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'deep-inspection'
            unsupported-ssl-cipher:
                type: str
                description: no description
                choices:
                    - 'block'
                    - 'allow'
            unsupported-ssl-negotiation:
                type: str
                description: no description
                choices:
                    - 'block'
                    - 'allow'
            untrusted-server-cert:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            unsupported-ssl-version:
                type: str
                description: no description
                choices:
                    - 'block'
                    - 'allow'
                    - 'inspect'

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
      fmgr_firewall_sslsshprofile_dot:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         ssl-ssh-profile: <your own value>
         firewall_sslsshprofile_dot:
            cert-validation-failure: <value in [allow, block, ignore]>
            cert-validation-timeout: <value in [allow, block, ignore]>
            client-certificate: <value in [bypass, inspect, block]>
            expired-server-cert: <value in [allow, block, ignore]>
            proxy-after-tcp-handshake: <value in [disable, enable]>
            revoked-server-cert: <value in [allow, block, ignore]>
            sni-server-cert-check: <value in [enable, strict, disable]>
            status: <value in [disable, deep-inspection]>
            unsupported-ssl-cipher: <value in [block, allow]>
            unsupported-ssl-negotiation: <value in [block, allow]>
            untrusted-server-cert: <value in [allow, block, ignore]>
            unsupported-ssl-version: <value in [block, allow, inspect]>

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
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot',
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot/{dot}',
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot/{dot}'
    ]

    url_params = ['adom', 'ssl-ssh-profile']
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'ssl-ssh-profile': {
            'required': True,
            'type': 'str'
        },
        'firewall_sslsshprofile_dot': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'cert-validation-failure': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'cert-validation-timeout': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'client-certificate': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'bypass',
                        'inspect',
                        'block'
                    ],
                    'type': 'str'
                },
                'expired-server-cert': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'proxy-after-tcp-handshake': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'revoked-server-cert': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'sni-server-cert-check': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'enable',
                        'strict',
                        'disable'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'deep-inspection'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl-cipher': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'block',
                        'allow'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl-negotiation': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'block',
                        'allow'
                    ],
                    'type': 'str'
                },
                'untrusted-server-cert': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl-version': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'block',
                        'allow',
                        'inspect'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_dot'),
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
