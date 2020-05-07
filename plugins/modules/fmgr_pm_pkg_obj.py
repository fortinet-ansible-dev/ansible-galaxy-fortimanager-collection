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
module: fmgr_pm_pkg_obj
short_description: no description
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ delete get set update ] the following apis.
    - /pm/pkg/adom/{adom}/{pkg_path}
    - /pm/pkg/global/{pkg_path}
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
    loose_validation:
        description: Do parameter validation in a loose way
        required: False
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock in case FortiManager running in workspace mode
        required: False
        type: string
        choices:
          - global
          - custom adom
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: False
        type: integer
        default: 300
    url_params:
        description: the parameters in url path
        required: True
        type: dict
        suboptions:
            adom:
                type: str
                description: the domain prefix, the none and global are reserved
                choices:
                  - none
                  - global
                  - custom dom
            pkg_path:
                type: str
    schema_object0:
        methods: [delete]
        description: ''
        api_categories: [api_tag0]
        api_tag0:
    schema_object1:
        methods: [get]
        description: ''
        api_categories: [api_tag0]
        api_tag0:
            fields:
                -
                    -
                        type: str
                        choices:
                            - 'name'
                            - 'obj ver'
                            - 'oid'
                            - 'scope member'
                            - 'type'
    schema_object2:
        methods: [set, update]
        description: ''
        api_categories: [api_tag0]
        api_tag0:
            data:
                name:
                    type: str
                obj ver:
                    type: int
                oid:
                    type: int
                package setting:
                    central-nat:
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    consolidated-firewall-mode:
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy-implicit-log:
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy6-implicit-log:
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    inspection-mode:
                        type: str
                        choices:
                            - 'proxy'
                            - 'flow'
                    ngfw-mode:
                        type: str
                        choices:
                            - 'profile-based'
                            - 'policy-based'
                    ssl-ssh-profile:
                        type: str
                scope member:
                    -
                        name:
                            type: str
                        vdom:
                            type: str
                type:
                    type: str
                    choices:
                        - 'pkg'
                        - 'folder'

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

    - name: REQUESTING /PM/PKG/{PKG_PATH}
      fmgr_pm_pkg_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg_path: <value of string>
         params:
            -
               fields:
                 -
                    - <value in [name, obj ver, oid, ...]>

    - name: REQUESTING /PM/PKG/{PKG_PATH}
      fmgr_pm_pkg_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg_path: <value of string>
         params:
            -
               data:
                  name: <value of string>
                  obj ver: <value of integer>
                  oid: <value of integer>
                  package setting:
                     central-nat: <value in [disable, enable]>
                     consolidated-firewall-mode: <value in [disable, enable]>
                     fwpolicy-implicit-log: <value in [disable, enable]>
                     fwpolicy6-implicit-log: <value in [disable, enable]>
                     inspection-mode: <value in [proxy, flow]>
                     ngfw-mode: <value in [profile-based, policy-based]>
                     ssl-ssh-profile: <value of string>
                  scope member:
                    -
                        name: <value of string>
                        vdom: <value of string>
                  type: <value in [pkg, folder]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[delete, set, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/pkg/adom/{adom}/{pkg_path}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            name:
               type: str
            obj ver:
               type: int
            oid:
               type: int
            package setting:
               central-nat:
                  type: str
               consolidated-firewall-mode:
                  type: str
               fwpolicy-implicit-log:
                  type: str
               fwpolicy6-implicit-log:
                  type: str
               inspection-mode:
                  type: str
               ngfw-mode:
                  type: str
               ssl-ssh-profile:
                  type: str
            scope member:
               type: array
               suboptions:
                  name:
                     type: str
                  vdom:
                     type: str
            type:
               type: str
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/pkg/adom/{adom}/{pkg_path}'

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
        '/pm/pkg/adom/{adom}/{pkg_path}',
        '/pm/pkg/global/{pkg_path}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'pkg_path',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'name',
                                'obj ver',
                                'oid',
                                'scope member',
                                'type'
                            ]
                        }
                    }
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object2': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'name': {
                            'type': 'string'
                        },
                        'obj ver': {
                            'type': 'integer'
                        },
                        'oid': {
                            'type': 'integer'
                        },
                        'package setting': {
                            'central-nat': {
                                'type': 'string',
                                'enum': [
                                    'disable',
                                    'enable'
                                ]
                            },
                            'consolidated-firewall-mode': {
                                'type': 'string',
                                'enum': [
                                    'disable',
                                    'enable'
                                ]
                            },
                            'fwpolicy-implicit-log': {
                                'type': 'string',
                                'enum': [
                                    'disable',
                                    'enable'
                                ]
                            },
                            'fwpolicy6-implicit-log': {
                                'type': 'string',
                                'enum': [
                                    'disable',
                                    'enable'
                                ]
                            },
                            'inspection-mode': {
                                'type': 'string',
                                'enum': [
                                    'proxy',
                                    'flow'
                                ]
                            },
                            'ngfw-mode': {
                                'type': 'string',
                                'enum': [
                                    'profile-based',
                                    'policy-based'
                                ]
                            },
                            'ssl-ssh-profile': {
                                'type': 'string'
                            }
                        },
                        'scope member': {
                            'type': 'array',
                            'items': {
                                'name': {
                                    'type': 'string'
                                },
                                'vdom': {
                                    'type': 'string'
                                }
                            }
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'pkg',
                                'folder'
                            ]
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
            'delete': 'object0',
            'get': 'object1',
            'set': 'object2',
            'update': 'object2'
        }
    }

    module_arg_spec = {
        'loose_validation': {
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
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'delete',
                'get',
                'set',
                'update'
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
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation == False:
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
