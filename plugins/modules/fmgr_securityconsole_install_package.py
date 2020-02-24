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
module: fmgr_securityconsole_install_package
short_description: Copy and install a policy package to devices.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ exec ] the following apis.
    - /securityconsole/install/package
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    schema_object0:
        methods: [exec]
        description: 'Copy and install a policy package to devices.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                adom:
                    type: str
                    description: 'Source ADOM name.'
                adom_rev_comments:
                    type: str
                    description: 'If "generate_rev" flag is set, the comment for the new ADOM revision.'
                adom_rev_name:
                    type: str
                    description: 'If "generate_rev" flag is set, the name for the new ADOM revision.'
                dev_rev_comments:
                    type: str
                    description: 'Comments for the device configuration revision that will be generated during install.'
                flags:
                    -
                        type: str
                        choices:
                            - 'none'
                            - 'cp_all_objs'
                            - 'preview'
                            - 'generate_rev'
                            - 'copy_assigned_pkg'
                            - 'unassign'
                            - 'ifpolicy_only'
                            - 'no_ifpolicy'
                            - 'objs_only'
                            - 'auto_lock_ws'
                            - 'check_pkg_st'
                            - 'copy_only'
                pkg:
                    type: str
                    description: 'Source package path and name.'
                scope:
                    -
                        name:
                            type: str
                        vdom:
                            type: str

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /SECURITYCONSOLE/INSTALL/PACKAGE
      fmgr_securityconsole_install_package:
         method: <value in [exec]>
         params:
            -
               data:
                  adom: <value of string>
                  adom_rev_comments: <value of string>
                  adom_rev_name: <value of string>
                  dev_rev_comments: <value of string>
                  flags:
                    - <value in [none, cp_all_objs, preview, ...]>
                  pkg: <value of string>
                  scope:
                    -
                        name: <value of string>
                        vdom: <value of string>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[exec]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            task:
               type: str
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/securityconsole/install/package'

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/securityconsole/install/package'
    ]

    url_schema = [
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'adom': {
                            'type': 'string'
                        },
                        'adom_rev_comments': {
                            'type': 'string'
                        },
                        'adom_rev_name': {
                            'type': 'string'
                        },
                        'dev_rev_comments': {
                            'type': 'string'
                        },
                        'flags': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'none',
                                    'cp_all_objs',
                                    'preview',
                                    'generate_rev',
                                    'copy_assigned_pkg',
                                    'unassign',
                                    'ifpolicy_only',
                                    'no_ifpolicy',
                                    'objs_only',
                                    'auto_lock_ws',
                                    'check_pkg_st',
                                    'copy_only'
                                ]
                            }
                        },
                        'pkg': {
                            'type': 'string'
                        },
                        'scope': {
                            'type': 'array',
                            'items': {
                                'name': {
                                    'type': 'string'
                                },
                                'vdom': {
                                    'type': 'string'
                                }
                            }
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'exec': 'object0'
        }
    }

    module_arg_spec = {
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'exec'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
