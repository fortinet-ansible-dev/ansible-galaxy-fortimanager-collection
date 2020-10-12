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
module: fmgr_icap_profile
short_description: Configure ICAP profiles.
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
    icap_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            methods:
                description: no description
                type: list
                choices:
                 - delete
                 - get
                 - head
                 - options
                 - post
                 - put
                 - trace
                 - other
            name:
                type: str
                description: 'ICAP profile name.'
            replacemsg-group:
                type: str
                description: 'Replacement message group.'
            request:
                type: str
                description: 'Enable/disable whether an HTTP request is passed to an ICAP server.'
                choices:
                    - 'disable'
                    - 'enable'
            request-failure:
                type: str
                description: 'Action to take if the ICAP server cannot be contacted when processing an HTTP request.'
                choices:
                    - 'error'
                    - 'bypass'
            request-path:
                type: str
                description: 'Path component of the ICAP URI that identifies the HTTP request processing service.'
            request-server:
                type: str
                description: 'ICAP server to use for an HTTP request.'
            response:
                type: str
                description: 'Enable/disable whether an HTTP response is passed to an ICAP server.'
                choices:
                    - 'disable'
                    - 'enable'
            response-failure:
                type: str
                description: 'Action to take if the ICAP server cannot be contacted when processing an HTTP response.'
                choices:
                    - 'error'
                    - 'bypass'
            response-path:
                type: str
                description: 'Path component of the ICAP URI that identifies the HTTP response processing service.'
            response-server:
                type: str
                description: 'ICAP server to use for an HTTP response.'
            streaming-content-bypass:
                type: str
                description: 'Enable/disable bypassing of ICAP server for streaming content.'
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
    - name: Configure ICAP profiles.
      fmgr_icap_profile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         icap_profile:
            methods:
              - delete
              - get
              - head
              - options
              - post
              - put
              - trace
              - other
            name: <value of string>
            replacemsg-group: <value of string>
            request: <value in [disable, enable]>
            request-failure: <value in [error, bypass]>
            request-path: <value of string>
            request-server: <value of string>
            response: <value in [disable, enable]>
            response-failure: <value in [error, bypass]>
            response-path: <value of string>
            response-server: <value of string>
            streaming-content-bypass: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/icap/profile',
        '/pm/config/global/obj/icap/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
        '/pm/config/global/obj/icap/profile/{profile}'
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
        'icap_profile': {
            'required': False,
            'type': 'dict',
            'options': {
                'methods': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'delete',
                        'get',
                        'head',
                        'options',
                        'post',
                        'put',
                        'trace',
                        'other'
                    ]
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'type': 'str'
                },
                'request': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'request-failure': {
                    'required': False,
                    'choices': [
                        'error',
                        'bypass'
                    ],
                    'type': 'str'
                },
                'request-path': {
                    'required': False,
                    'type': 'str'
                },
                'request-server': {
                    'required': False,
                    'type': 'str'
                },
                'response': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'response-failure': {
                    'required': False,
                    'choices': [
                        'error',
                        'bypass'
                    ],
                    'type': 'str'
                },
                'response-path': {
                    'required': False,
                    'type': 'str'
                },
                'response-server': {
                    'required': False,
                    'type': 'str'
                },
                'streaming-content-bypass': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_profile'),
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
