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
module: fmgr_securityconsole_import_dev_objs
short_description: Import objects from device to ADOM, or from ADOM to Global.
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
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    securityconsole_import_dev_objs:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            add_mappings:
                type: str
                default: 'disable'
                description: 'Automatically add required dynamic mappings for the device during the search stages.<br/>When used in policy_search action, ad...'
                choices:
                    - 'disable'
                    - 'enable'
            adom:
                type: str
                description: 'Source ADOM name.'
            dst_name:
                type: str
                description: 'Name of the policy package where the objects are to be imported. If the package does not already exist in the database, a new ...'
            dst_parent:
                type: str
                description: 'Path to the folder for the target package. If the package is to be placed in root, leave this field blank.'
            if_all_objs:
                type: str
                default: 'none'
                description: no description
                choices:
                    - 'none'
                    - 'all'
                    - 'filter'
            if_all_policy:
                type: str
                default: 'disable'
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            import_action:
                type: str
                default: 'do'
                description:
                 - 'do - Perform the policy and object import.'
                 - 'policy_search - Preprocess and scan through device database to gather information about policies that need to be imported. Can automatic...'
                 - 'obj_search - Preprocess and scan through device database to collect objects that are required to be imported. Can automatically add obje...'
                choices:
                    - 'do'
                    - 'policy_search'
                    - 'obj_search'
            name:
                type: str
                description: 'Source device name.'
            position:
                type: str
                default: 'top'
                description: no description
                choices:
                    - 'bottom'
                    - 'top'
            vdom:
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
    - name: Import objects from device to ADOM, or from ADOM to Global.
      fmgr_securityconsole_import_dev_objs:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         securityconsole_import_dev_objs:
            add_mappings: <value in [disable, enable]>
            adom: <value of string>
            dst_name: <value of string>
            dst_parent: <value of string>
            if_all_objs: <value in [none, all, filter]>
            if_all_policy: <value in [disable, enable]>
            import_action: <value in [do, policy_search, obj_search]>
            name: <value of string>
            position: <value in [bottom, top]>
            vdom: <value of string>

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
        '/securityconsole/import/dev/objs'
    ]

    perobject_jrpc_urls = [
        '/securityconsole/import/dev/objs/{objs}'
    ]

    url_params = []
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
        'securityconsole_import_dev_objs': {
            'required': False,
            'type': 'dict',
            'options': {
                'add_mappings': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'adom': {
                    'required': False,
                    'type': 'str'
                },
                'dst_name': {
                    'required': False,
                    'type': 'str'
                },
                'dst_parent': {
                    'required': False,
                    'type': 'str'
                },
                'if_all_objs': {
                    'required': False,
                    'choices': [
                        'none',
                        'all',
                        'filter'
                    ],
                    'type': 'str'
                },
                'if_all_policy': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'import_action': {
                    'required': False,
                    'choices': [
                        'do',
                        'policy_search',
                        'obj_search'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'position': {
                    'required': False,
                    'choices': [
                        'bottom',
                        'top'
                    ],
                    'type': 'str'
                },
                'vdom': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_import_dev_objs'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, None, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_exec()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
