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
module: fmgr_vpnsslweb_hostchecksoftware
short_description: SSL-VPN host check software.
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
    vpnsslweb_hostchecksoftware:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            check-item-list:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'deny'
                            - 'require'
                    id:
                        type: int
                        description: 'ID (0 - 4294967295).'
                    md5s:
                        description: no description
                        type: str
                    target:
                        type: str
                        description: 'Target.'
                    type:
                        type: str
                        description: 'Type.'
                        choices:
                            - 'file'
                            - 'registry'
                            - 'process'
                    version:
                        type: str
                        description: 'Version.'
            guid:
                type: str
                description: 'Globally unique ID.'
            name:
                type: str
                description: 'Name.'
            os-type:
                type: str
                description: 'OS type.'
                choices:
                    - 'macos'
                    - 'windows'
            type:
                type: str
                description: 'Type.'
                choices:
                    - 'av'
                    - 'fw'
            version:
                type: str
                description: 'Version.'

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
    - name: SSL-VPN host check software.
      fmgr_vpnsslweb_hostchecksoftware:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         vpnsslweb_hostchecksoftware:
            check-item-list:
              -
                  action: <value in [deny, require]>
                  id: <value of integer>
                  md5s: <value of string>
                  target: <value of string>
                  type: <value in [file, registry, process]>
                  version: <value of string>
            guid: <value of string>
            name: <value of string>
            os-type: <value in [macos, windows]>
            type: <value in [av, fw]>
            version: <value of string>

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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software',
        '/pm/config/global/obj/vpn/ssl/web/host-check-software'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
        '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
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
        'vpnsslweb_hostchecksoftware': {
            'required': False,
            'type': 'dict',
            'options': {
                'check-item-list': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'deny',
                                'require'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'md5s': {
                            'required': False,
                            'type': 'str'
                        },
                        'target': {
                            'required': False,
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'choices': [
                                'file',
                                'registry',
                                'process'
                            ],
                            'type': 'str'
                        },
                        'version': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'guid': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'os-type': {
                    'required': False,
                    'choices': [
                        'macos',
                        'windows'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'av',
                        'fw'
                    ],
                    'type': 'str'
                },
                'version': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_hostchecksoftware'),
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
