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
module: fmgr_waf_profile_urlaccess
short_description: URL access list
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
    profile:
        description: the parameter (profile) in requested url
        type: str
        required: true
    waf_profile_urlaccess:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            access-pattern:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: 'URL access pattern ID.'
                    negate:
                        type: str
                        description: 'Enable/disable match negation.'
                        choices:
                            - 'disable'
                            - 'enable'
                    pattern:
                        type: str
                        description: 'URL pattern.'
                    regex:
                        type: str
                        description: 'Enable/disable regular expression based pattern match.'
                        choices:
                            - 'disable'
                            - 'enable'
                    srcaddr:
                        type: str
                        description: 'Source address.'
            action:
                type: str
                description: 'Action.'
                choices:
                    - 'bypass'
                    - 'permit'
                    - 'block'
            address:
                type: str
                description: 'Host address.'
            id:
                type: int
                description: 'URL access ID.'
            log:
                type: str
                description: 'Enable/disable logging.'
                choices:
                    - 'disable'
                    - 'enable'
            severity:
                type: str
                description: 'Severity.'
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'

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
    - name: URL access list
      fmgr_waf_profile_urlaccess:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         profile: <your own value>
         state: <value in [present, absent]>
         waf_profile_urlaccess:
            access-pattern:
              -
                  id: <value of integer>
                  negate: <value in [disable, enable]>
                  pattern: <value of string>
                  regex: <value in [disable, enable]>
                  srcaddr: <value of string>
            action: <value in [bypass, permit, block]>
            address: <value of string>
            id: <value of integer>
            log: <value in [disable, enable]>
            severity: <value in [low, medium, high]>

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
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access',
        '/pm/config/global/obj/waf/profile/{profile}/url-access'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
        '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
    ]

    url_params = ['adom', 'profile']
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'profile': {
            'required': True,
            'type': 'str'
        },
        'waf_profile_urlaccess': {
            'required': False,
            'type': 'dict',
            'options': {
                'access-pattern': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'negate': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pattern': {
                            'required': False,
                            'type': 'str'
                        },
                        'regex': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'srcaddr': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'action': {
                    'required': False,
                    'choices': [
                        'bypass',
                        'permit',
                        'block'
                    ],
                    'type': 'str'
                },
                'address': {
                    'required': False,
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'type': 'int'
                },
                'log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'severity': {
                    'required': False,
                    'choices': [
                        'low',
                        'medium',
                        'high'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_urlaccess'),
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
