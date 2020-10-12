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
module: fmgr_user_local
short_description: Configure local users.
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
    user_local:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auth-concurrent-override:
                type: str
                description: 'Enable/disable overriding the policy-auth-concurrent under config system global.'
                choices:
                    - 'disable'
                    - 'enable'
            auth-concurrent-value:
                type: int
                description: 'Maximum number of concurrent logins permitted from the same user.'
            authtimeout:
                type: int
                description: 'Time in minutes before the authentication timeout for a user is reached.'
            email-to:
                type: str
                description: 'Two-factor recipients email address.'
            fortitoken:
                type: str
                description: 'Two-factor recipients FortiToken serial number.'
            id:
                type: int
                description: 'User ID.'
            ldap-server:
                type: str
                description: 'Name of LDAP server with which the user must authenticate.'
            name:
                type: str
                description: 'User name.'
            passwd:
                description: no description
                type: str
            passwd-policy:
                type: str
                description: 'Password policy to apply to this user, as defined in config user password-policy.'
            ppk-identity:
                type: str
                description: 'IKEv2 Postquantum Preshared Key Identity.'
            ppk-secret:
                description: no description
                type: str
            radius-server:
                type: str
                description: 'Name of RADIUS server with which the user must authenticate.'
            sms-custom-server:
                type: str
                description: 'Two-factor recipients SMS server.'
            sms-phone:
                type: str
                description: 'Two-factor recipients mobile phone number.'
            sms-server:
                type: str
                description: 'Send SMS through FortiGuard or other external server.'
                choices:
                    - 'fortiguard'
                    - 'custom'
            status:
                type: str
                description: 'Enable/disable allowing the local user to authenticate with the FortiGate unit.'
                choices:
                    - 'disable'
                    - 'enable'
            tacacs+-server:
                type: str
                description: 'Name of TACACS+ server with which the user must authenticate.'
            two-factor:
                type: str
                description: 'Enable/disable two-factor authentication.'
                choices:
                    - 'disable'
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
                    - 'fortitoken-cloud'
            type:
                type: str
                description: 'Authentication method.'
                choices:
                    - 'password'
                    - 'radius'
                    - 'tacacs+'
                    - 'ldap'
            workstation:
                type: str
                description: 'Name of the remote user workstation, if you want to limit the user to authenticate only from a particular workstation.'

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
    - name: Configure local users.
      fmgr_user_local:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         user_local:
            auth-concurrent-override: <value in [disable, enable]>
            auth-concurrent-value: <value of integer>
            authtimeout: <value of integer>
            email-to: <value of string>
            fortitoken: <value of string>
            id: <value of integer>
            ldap-server: <value of string>
            name: <value of string>
            passwd: <value of string>
            passwd-policy: <value of string>
            ppk-identity: <value of string>
            ppk-secret: <value of string>
            radius-server: <value of string>
            sms-custom-server: <value of string>
            sms-phone: <value of string>
            sms-server: <value in [fortiguard, custom]>
            status: <value in [disable, enable]>
            tacacs+-server: <value of string>
            two-factor: <value in [disable, fortitoken, email, ...]>
            type: <value in [password, radius, tacacs+, ...]>
            workstation: <value of string>

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
        '/pm/config/adom/{adom}/obj/user/local',
        '/pm/config/global/obj/user/local'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/local/{local}',
        '/pm/config/global/obj/user/local/{local}'
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
        'user_local': {
            'required': False,
            'type': 'dict',
            'options': {
                'auth-concurrent-override': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auth-concurrent-value': {
                    'required': False,
                    'type': 'int'
                },
                'authtimeout': {
                    'required': False,
                    'type': 'int'
                },
                'email-to': {
                    'required': False,
                    'type': 'str'
                },
                'fortitoken': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': False,
                    'type': 'int'
                },
                'ldap-server': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'passwd': {
                    'required': False,
                    'type': 'str'
                },
                'passwd-policy': {
                    'required': False,
                    'type': 'str'
                },
                'ppk-identity': {
                    'required': False,
                    'type': 'str'
                },
                'ppk-secret': {
                    'required': False,
                    'type': 'str'
                },
                'radius-server': {
                    'required': False,
                    'type': 'str'
                },
                'sms-custom-server': {
                    'required': False,
                    'type': 'str'
                },
                'sms-phone': {
                    'required': False,
                    'type': 'str'
                },
                'sms-server': {
                    'required': False,
                    'choices': [
                        'fortiguard',
                        'custom'
                    ],
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
                'tacacs+-server': {
                    'required': False,
                    'type': 'str'
                },
                'two-factor': {
                    'required': False,
                    'choices': [
                        'disable',
                        'fortitoken',
                        'email',
                        'sms',
                        'fortitoken-cloud'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'password',
                        'radius',
                        'tacacs+',
                        'ldap'
                    ],
                    'type': 'str'
                },
                'workstation': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_local'),
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
