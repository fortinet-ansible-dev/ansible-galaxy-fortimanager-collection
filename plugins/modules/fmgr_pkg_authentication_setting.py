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
module: fmgr_pkg_authentication_setting
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_authentication_setting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            active-auth-scheme:
                type: str
                description: no description
            auth-https:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            captive-portal:
                type: str
                description: no description
            captive-portal-ip:
                type: str
                description: no description
            captive-portal-ip6:
                type: str
                description: no description
            captive-portal-port:
                type: int
                description: no description
            captive-portal-ssl-port:
                type: int
                description: no description
            captive-portal-type:
                type: str
                description: no description
                choices:
                    - 'fqdn'
                    - 'ip'
            captive-portal6:
                type: str
                description: no description
            rewrite-https-port:
                type: int
                description: no description
            sso-auth-scheme:
                type: str
                description: no description
            dev-range:
                type: str
                description: no description
            user-cert-ca:
                type: str
                description: no description
            cert-auth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            cert-captive-portal:
                type: str
                description: no description
            cert-captive-portal-ip:
                type: str
                description: no description
            cert-captive-portal-port:
                type: int
                description: no description
            cookie-max-age:
                type: int
                description: no description
            cookie-refresh-div:
                type: int
                description: no description
            ip-auth-cookie:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            persistent-cookie:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            update-time:
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
      fmgr_pkg_authentication_setting:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pkg: <your own value>
         pkg_authentication_setting:
            active-auth-scheme: <value of string>
            auth-https: <value in [disable, enable]>
            captive-portal: <value of string>
            captive-portal-ip: <value of string>
            captive-portal-ip6: <value of string>
            captive-portal-port: <value of integer>
            captive-portal-ssl-port: <value of integer>
            captive-portal-type: <value in [fqdn, ip]>
            captive-portal6: <value of string>
            rewrite-https-port: <value of integer>
            sso-auth-scheme: <value of string>
            dev-range: <value of string>
            user-cert-ca: <value of string>
            cert-auth: <value in [disable, enable]>
            cert-captive-portal: <value of string>
            cert-captive-portal-ip: <value of string>
            cert-captive-portal-port: <value of integer>
            cookie-max-age: <value of integer>
            cookie-refresh-div: <value of integer>
            ip-auth-cookie: <value in [disable, enable]>
            persistent-cookie: <value in [disable, enable]>
            update-time: <value of string>

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
        '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting/{setting}'
    ]

    url_params = ['adom', 'pkg']
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_authentication_setting': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'active-auth-scheme': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'auth-https': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'captive-portal': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'captive-portal-ip': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'captive-portal-ip6': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'captive-portal-port': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'captive-portal-ssl-port': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'captive-portal-type': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'fqdn',
                        'ip'
                    ],
                    'type': 'str'
                },
                'captive-portal6': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'rewrite-https-port': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'sso-auth-scheme': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dev-range': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'user-cert-ca': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'cert-auth': {
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
                'cert-captive-portal': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'cert-captive-portal-ip': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'cert-captive-portal-port': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'cookie-max-age': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'cookie-refresh-div': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ip-auth-cookie': {
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
                'persistent-cookie': {
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
                'update-time': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_authentication_setting'),
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
