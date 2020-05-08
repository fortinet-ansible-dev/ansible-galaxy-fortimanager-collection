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
module: fmgr_dvmdb_group_obj
short_description: Device group table.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ delete get set update add ] the following apis.
    - /dvmdb/adom/{adom}/group/{group}
    - /dvmdb/group/{group}
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
            group:
                type: str
    schema_object0:
        methods: [delete]
        description: 'Device group table.'
        api_categories: [api_tag0, api_tag1]
        api_tag0:
        api_tag1:
            data:
                -
                    name:
                        type: str
                    vdom:
                        type: str
    schema_object1:
        methods: [get]
        description: 'Device group table.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the object will be returned.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'chksum - Return the check-sum value instead of attributes.'
                choices:
                    - 'object member'
                    - 'chksum'
    schema_object2:
        methods: [set, update]
        description: 'Device group table.'
        api_categories: [api_tag0, api_tag1]
        api_tag0:
            data:
                desc:
                    type: str
                meta fields:
                    type: str
                name:
                    type: str
                os_type:
                    type: str
                    default: 'unknown'
                    choices:
                        - 'unknown'
                        - 'fos'
                        - 'fsw'
                        - 'foc'
                        - 'fml'
                        - 'faz'
                        - 'fwb'
                        - 'fch'
                        - 'fct'
                        - 'log'
                        - 'fmg'
                        - 'fsa'
                        - 'fdd'
                        - 'fac'
                        - 'fpx'
                type:
                    type: str
                    default: 'normal'
                    choices:
                        - 'normal'
                        - 'default'
                        - 'auto'
        api_tag1:
            data:
                -
                    name:
                        type: str
                    vdom:
                        type: str
    schema_object3:
        methods: [add]
        description: 'Device group table.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    name:
                        type: str
                    vdom:
                        type: str

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

    - name: REQUESTING /DVMDB/GROUP/{GROUP}
      fmgr_dvmdb_group_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [delete]>
         url_params:
            adom: <value in [none, global, custom dom]>
            group: <value of string>
         params:
            -
               data:
                 -
                     name: <value of string>
                     vdom: <value of string>

    - name: REQUESTING /DVMDB/GROUP/{GROUP}
      fmgr_dvmdb_group_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            group: <value of string>
         params:
            -
               option: <value in [object member, chksum]>

    - name: REQUESTING /DVMDB/GROUP/{GROUP}
      fmgr_dvmdb_group_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            group: <value of string>
         params:
            -
               data:
                  desc: <value of string>
                  meta fields: <value of string>
                  name: <value of string>
                  os_type: <value in [unknown, fos, fsw, ...] default: 'unknown'>
                  type: <value in [normal, default, auto] default: 'normal'>

    - name: REQUESTING /DVMDB/GROUP/{GROUP}
      fmgr_dvmdb_group_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            group: <value of string>
         params:
            -
               data:
                 -
                     name: <value of string>
                     vdom: <value of string>

    - name: REQUESTING /DVMDB/GROUP/{GROUP}
      fmgr_dvmdb_group_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [add]>
         url_params:
            adom: <value in [none, global, custom dom]>
            group: <value of string>
         params:
            -
               data:
                 -
                     name: <value of string>
                     vdom: <value of string>

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
            example: '/dvmdb/adom/{adom}/group/{group}'
return_of_api_category_1:
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
            example: '/dvmdb/adom/{adom}/group/{group}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            desc:
               type: str
            meta fields:
               type: str
            name:
               type: str
            os_type:
               type: str
               example: 'unknown'
            type:
               type: str
               example: 'normal'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/dvmdb/adom/{adom}/group/{group}'
return_of_api_category_0:
   description: items returned for method:[add]
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
            example: '/dvmdb/adom/{adom}/group/{group}'

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
        '/dvmdb/adom/{adom}/group/{group}',
        '/dvmdb/group/{group}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'group',
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
                },
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
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
                    'api_tag': 1
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 1
                }
            ],
            'object1': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'object member',
                            'chksum'
                        ]
                    },
                    'api_tag': 0
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
                        'desc': {
                            'type': 'string'
                        },
                        'meta fields': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'os_type': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                'fos',
                                'fsw',
                                'foc',
                                'fml',
                                'faz',
                                'fwb',
                                'fch',
                                'fct',
                                'log',
                                'fmg',
                                'fsa',
                                'fdd',
                                'fac',
                                'fpx'
                            ]
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'normal',
                                'default',
                                'auto'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                },
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
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
                    'api_tag': 1
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 1
                }
            ],
            'object3': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
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
            'update': 'object2',
            'add': 'object3'
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
                'update',
                'add'
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
        if loose_validation is False:
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
