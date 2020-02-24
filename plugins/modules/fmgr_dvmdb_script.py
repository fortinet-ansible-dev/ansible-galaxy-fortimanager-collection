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
module: fmgr_dvmdb_script
short_description: Script table.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /dvmdb/adom/{adom}/script
    - /dvmdb/global/script
    - /dvmdb/script
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
    schema_object0:
        methods: [add, set, update]
        description: 'Script table.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    content:
                        type: str
                        description: 'The full content of the script result log.'
                    desc:
                        type: str
                    filter_build:
                        type: int
                        description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_...'
                    filter_device:
                        type: int
                        description: 'Name or id of an existing device in the database. It has no effect if target is "adom_database".'
                    filter_hostname:
                        type: str
                        description: 'The value has no effect if target is "adom_database".'
                    filter_ostype:
                        type: str
                        default: 'unknown'
                        description: 'The value has no effect if target is "adom_database".'
                        choices:
                            - 'unknown'
                            - 'fos'
                    filter_osver:
                        type: str
                        default: 'unknown'
                        description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_...'
                        choices:
                            - 'unknown'
                            - '4.00'
                            - '5.00'
                    filter_platform:
                        type: str
                        description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_...'
                    filter_serial:
                        type: str
                        description: 'The value has no effect if target is "adom_database".'
                    modification_time:
                        type: str
                        description: 'It is a read-only attribute indicating the time when the script was created or modified. The value will be ignored in ...'
                    name:
                        type: str
                    script_schedule:
                        -
                            datetime:
                                type: str
                                description:
                                 - 'Indicates the date and time of the schedule. It should follow the following format for each scheduling type:'
                                 - 'onetime: "YYYY-MM-DD hh:mm:ss"'
                                 - 'daily: "hh:mm"'
                                 - 'weekly: "hh:mm"'
                                 - 'monthly: "DD hh:mm"'
                            day_of_week:
                                type: str
                                default: 'sun'
                                choices:
                                    - 'unknown'
                                    - 'sun'
                                    - 'mon'
                                    - 'tue'
                                    - 'wed'
                                    - 'thu'
                                    - 'fri'
                                    - 'sat'
                            device:
                                type: int
                                description: 'Name or id of an existing device in the database.'
                            name:
                                type: str
                            run_on_db:
                                type: str
                                default: 'disable'
                                description: 'Indicates if the scheduled script should be executed on device database. It should always be disable for tcl s...'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            type:
                                type: str
                                choices:
                                    - 'auto'
                                    - 'onetime'
                                    - 'daily'
                                    - 'weekly'
                                    - 'monthly'
                    target:
                        type: str
                        default: 'device_database'
                        choices:
                            - 'device_database'
                            - 'remote_device'
                            - 'adom_database'
                    type:
                        type: str
                        choices:
                            - 'cli'
                            - 'tcl'
                            - 'cligrp'
    schema_object1:
        methods: [get]
        description: 'Script table.'
        api_categories: [api_tag0]
        api_tag0:
            expand member:
                type: str
                description: 'Fetch all or selected attributes of object members.'
            fields:
                -
                    -
                        type: str
                        choices:
                            - 'content'
                            - 'desc'
                            - 'filter_build'
                            - 'filter_device'
                            - 'filter_hostname'
                            - 'filter_ostype'
                            - 'filter_osver'
                            - 'filter_platform'
                            - 'filter_serial'
                            - 'modification_time'
                            - 'name'
                            - 'target'
                            - 'type'
            filter:
                -
                    type: str
            loadsub:
                type: int
                description: 'Enable or disable the return of any sub-objects. If not specified, the default is to return all sub-objects.'
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.'
                 - 'count - Return the number of matching entries instead of the actual entry data.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'syntax - Return the attribute syntax of a table or an object, instead of the actual entry data. All filter parameters will be ignored.'
                choices:
                    - 'count'
                    - 'object member'
                    - 'syntax'
            range:
                -
                    type: int
            sortings:
                -
                    varidic.attr_name:
                        type: int
                        choices:
                            - 1
                            - -1

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /DVMDB/SCRIPT
      fmgr_dvmdb_script:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     content: <value of string>
                     desc: <value of string>
                     filter_build: <value of integer>
                     filter_device: <value of integer>
                     filter_hostname: <value of string>
                     filter_ostype: <value in [unknown, fos] default: 'unknown'>
                     filter_osver: <value in [unknown, 4.00, 5.00] default: 'unknown'>
                     filter_platform: <value of string>
                     filter_serial: <value of string>
                     modification_time: <value of string>
                     name: <value of string>
                     script_schedule:
                       -
                           datetime: <value of string>
                           day_of_week: <value in [unknown, sun, mon, ...] default: 'sun'>
                           device: <value of integer>
                           name: <value of string>
                           run_on_db: <value in [disable, enable] default: 'disable'>
                           type: <value in [auto, onetime, daily, ...]>
                     target: <value in [device_database, remote_device, adom_database] default: 'device_database'>
                     type: <value in [cli, tcl, cligrp]>

    - name: REQUESTING /DVMDB/SCRIPT
      fmgr_dvmdb_script:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               expand member: <value of string>
               fields:
                 -
                    - <value in [content, desc, filter_build, ...]>
               filter:
                 - <value of string>
               loadsub: <value of integer>
               option: <value in [count, object member, syntax]>
               range:
                 - <value of integer>
               sortings:
                 -
                     varidic.attr_name: <value in [1, -1]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[add, set, update]
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
            example: '/dvmdb/adom/{adom}/script'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            type: array
            suboptions:
               content:
                  type: str
                  description: 'The full content of the script result log.'
               desc:
                  type: str
               filter_build:
                  type: int
                  description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_databa...'
               filter_device:
                  type: int
                  description: 'Name or id of an existing device in the database. It has no effect if target is "adom_database".'
               filter_hostname:
                  type: str
                  description: 'The value has no effect if target is "adom_database".'
               filter_ostype:
                  type: str
                  description: 'The value has no effect if target is "adom_database".'
                  example: 'unknown'
               filter_osver:
                  type: str
                  description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_databa...'
                  example: 'unknown'
               filter_platform:
                  type: str
                  description: 'The value will be ignored in add/set/update requests if filter_ostype is not set. It has no effect if target is "adom_databa...'
               filter_serial:
                  type: str
                  description: 'The value has no effect if target is "adom_database".'
               modification_time:
                  type: str
                  description: 'It is a read-only attribute indicating the time when the script was created or modified. The value will be ignored in add/se...'
               name:
                  type: str
               script_schedule:
                  type: array
                  suboptions:
                     datetime:
                        type: str
                        description: |
                           'Indicates the date and time of the schedule. It should follow the following format for each scheduling type:'
                           'onetime: "YYYY-MM-DD hh:mm:ss"'
                           'daily: "hh:mm"'
                           'weekly: "hh:mm"'
                           'monthly: "DD hh:mm"'
                     day_of_week:
                        type: str
                        example: 'sun'
                     device:
                        type: int
                        description: 'Name or id of an existing device in the database.'
                     name:
                        type: str
                     run_on_db:
                        type: str
                        description: 'Indicates if the scheduled script should be executed on device database. It should always be disable for tcl scripts.'
                        example: 'disable'
                     type:
                        type: str
               target:
                  type: str
                  example: 'device_database'
               type:
                  type: str
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/dvmdb/adom/{adom}/script'

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
        '/dvmdb/adom/{adom}/script',
        '/dvmdb/global/script',
        '/dvmdb/script'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'content': {
                            'type': 'string'
                        },
                        'desc': {
                            'type': 'string'
                        },
                        'filter_build': {
                            'type': 'integer'
                        },
                        'filter_device': {
                            'type': 'integer'
                        },
                        'filter_hostname': {
                            'type': 'string'
                        },
                        'filter_ostype': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                'fos'
                            ]
                        },
                        'filter_osver': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                '4.00',
                                '5.00'
                            ]
                        },
                        'filter_platform': {
                            'type': 'string'
                        },
                        'filter_serial': {
                            'type': 'string'
                        },
                        'modification_time': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'script_schedule': {
                            'type': 'array',
                            'items': {
                                'datetime': {
                                    'type': 'string'
                                },
                                'day_of_week': {
                                    'type': 'string',
                                    'enum': [
                                        'unknown',
                                        'sun',
                                        'mon',
                                        'tue',
                                        'wed',
                                        'thu',
                                        'fri',
                                        'sat'
                                    ]
                                },
                                'device': {
                                    'type': 'integer'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'run_on_db': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
                                        'auto',
                                        'onetime',
                                        'daily',
                                        'weekly',
                                        'monthly'
                                    ]
                                }
                            }
                        },
                        'target': {
                            'type': 'string',
                            'enum': [
                                'device_database',
                                'remote_device',
                                'adom_database'
                            ]
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'cli',
                                'tcl',
                                'cligrp'
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
            'object1': [
                {
                    'type': 'string',
                    'name': 'expand member',
                    'api_tag': 0
                },
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'content',
                                'desc',
                                'filter_build',
                                'filter_device',
                                'filter_hostname',
                                'filter_ostype',
                                'filter_osver',
                                'filter_platform',
                                'filter_serial',
                                'modification_time',
                                'name',
                                'target',
                                'type'
                            ]
                        }
                    }
                },
                {
                    'name': 'filter',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'example': [
                                '<attr>',
                                '==',
                                'test'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'loadsub',
                    'api_tag': 0
                },
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'count',
                            'object member',
                            'syntax'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'name': 'range',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'integer',
                            'example': [
                                2,
                                5
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'name': 'sortings',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            '{attr_name}': {
                                'type': 'integer',
                                'enum': [
                                    1,
                                    -1
                                ]
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
            'add': 'object0',
            'get': 'object1',
            'set': 'object0',
            'update': 'object0'
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
                'add',
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
