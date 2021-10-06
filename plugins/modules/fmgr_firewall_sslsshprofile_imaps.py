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
module: fmgr_firewall_sslsshprofile_imaps
short_description: Configure IMAPS options.
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
    ssl-ssh-profile:
        description: the parameter (ssl-ssh-profile) in requested url
        type: str
        required: true
    firewall_sslsshprofile_imaps:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            allow-invalid-server-cert:
                type: str
                description: 'When enabled, allows SSL sessions whose server certificate validation failed.'
                choices:
                    - 'disable'
                    - 'enable'
            client-cert-request:
                type: str
                description: 'Action based on client certificate request.'
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ports:
                description: no description
                type: int
            status:
                type: str
                description: 'Configure protocol inspection status.'
                choices:
                    - 'disable'
                    - 'deep-inspection'
            unsupported-ssl:
                type: str
                description: 'Action based on the SSL encryption used being unsupported.'
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            untrusted-cert:
                type: str
                description: 'Allow, ignore, or block the untrusted SSL session server certificate.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            invalid-server-cert:
                type: str
                description: 'Allow or block the invalid SSL session server certificate.'
                choices:
                    - 'allow'
                    - 'block'
            sni-server-cert-check:
                type: str
                description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                choices:
                    - 'disable'
                    - 'enable'
                    - 'strict'
            untrusted-server-cert:
                type: str
                description: 'Allow, ignore, or block the untrusted SSL session server certificate.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            cert-validation-failure:
                type: str
                description: 'Action based on certificate validation failure.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            cert-validation-timeout:
                type: str
                description: 'Action based on certificate validation timeout.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            client-certificate:
                type: str
                description: 'Action based on received client certificate.'
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            expired-server-cert:
                type: str
                description: 'Action based on server certificate is expired.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            proxy-after-tcp-handshake:
                type: str
                description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                choices:
                    - 'disable'
                    - 'enable'
            revoked-server-cert:
                type: str
                description: 'Action based on server certificate is revoked.'
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            unsupported-ssl-cipher:
                type: str
                description: 'Action based on the SSL cipher used being unsupported.'
                choices:
                    - 'allow'
                    - 'block'
            unsupported-ssl-negotiation:
                type: str
                description: 'Action based on the SSL negotiation used being unsupported.'
                choices:
                    - 'allow'
                    - 'block'

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
    - name: Configure IMAPS options.
      fmgr_firewall_sslsshprofile_imaps:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         ssl-ssh-profile: <your own value>
         firewall_sslsshprofile_imaps:
            allow-invalid-server-cert: <value in [disable, enable]>
            client-cert-request: <value in [bypass, inspect, block]>
            ports: <value of integer>
            status: <value in [disable, deep-inspection]>
            unsupported-ssl: <value in [bypass, inspect, block]>
            untrusted-cert: <value in [allow, block, ignore]>
            invalid-server-cert: <value in [allow, block]>
            sni-server-cert-check: <value in [disable, enable, strict]>
            untrusted-server-cert: <value in [allow, block, ignore]>
            cert-validation-failure: <value in [allow, block, ignore]>
            cert-validation-timeout: <value in [allow, block, ignore]>
            client-certificate: <value in [bypass, inspect, block]>
            expired-server-cert: <value in [allow, block, ignore]>
            proxy-after-tcp-handshake: <value in [disable, enable]>
            revoked-server-cert: <value in [allow, block, ignore]>
            unsupported-ssl-cipher: <value in [allow, block]>
            unsupported-ssl-negotiation: <value in [allow, block]>

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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps/{imaps}',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps/{imaps}'
    ]

    url_params = ['adom', 'ssl-ssh-profile']
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'firewall_sslsshprofile_imaps': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'allow-invalid-server-cert': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'client-cert-request': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'bypass',
                        'inspect',
                        'block'
                    ],
                    'type': 'str'
                },
                'ports': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'deep-inspection'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'bypass',
                        'inspect',
                        'block'
                    ],
                    'type': 'str'
                },
                'untrusted-cert': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'invalid-server-cert': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'allow',
                        'block'
                    ],
                    'type': 'str'
                },
                'sni-server-cert-check': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'strict'
                    ],
                    'type': 'str'
                },
                'untrusted-server-cert': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'cert-validation-failure': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'block',
                        'ignore'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl-cipher': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'block'
                    ],
                    'type': 'str'
                },
                'unsupported-ssl-negotiation': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'block'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_imaps'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
