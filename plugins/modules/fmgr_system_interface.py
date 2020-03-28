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
module: fmgr_system_interface
short_description: Interface configuration.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /cli/global/system/interface
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
        methods: [add, set, update]
        description: 'Interface configuration.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    alias:
                        type: str
                        description: 'Alias.'
                    allowaccess:
                        -
                            type: str
                            choices:
                                - 'ping'
                                - 'https'
                                - 'ssh'
                                - 'snmp'
                                - 'http'
                                - 'webservice'
                                - 'https-logging'
                    description:
                        type: str
                        description: 'Description.'
                    ip:
                        type: str
                        default: '0.0.0.0 0.0.0.0'
                        description: 'IP address of interface.'
                    ipv6:
                        ip6-address:
                            type: str
                            default: '::/0'
                            description: 'IPv6 address/prefix of interface.'
                        ip6-allowaccess:
                            -
                                type: str
                                choices:
                                    - 'ping'
                                    - 'https'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'webservice'
                                    - 'https-logging'
                        ip6-autoconf:
                            type: str
                            default: 'enable'
                            description:
                             - 'Enable/disable address auto config (SLAAC).'
                             - 'disable - Disable setting.'
                             - 'enable - Enable setting.'
                            choices:
                                - 'disable'
                                - 'enable'
                    mtu:
                        type: int
                        default: 1500
                        description: 'Maximum transportation unit(68 - 9000).'
                    name:
                        type: str
                        description: 'Interface name.'
                    serviceaccess:
                        -
                            type: str
                            choices:
                                - 'fgtupdates'
                                - 'fclupdates'
                                - 'webfilter-antispam'
                    speed:
                        type: str
                        default: 'auto'
                        description:
                         - 'Speed.'
                         - 'auto - Auto adjust speed.'
                         - '10full - 10M full-duplex.'
                         - '10half - 10M half-duplex.'
                         - '100full - 100M full-duplex.'
                         - '100half - 100M half-duplex.'
                         - '1000full - 1000M full-duplex.'
                         - '10000full - 10000M full-duplex.'
                        choices:
                            - 'auto'
                            - '10full'
                            - '10half'
                            - '100full'
                            - '100half'
                            - '1000full'
                            - '10000full'
                    status:
                        type: str
                        default: 'up'
                        description:
                         - 'Interface status.'
                         - 'down - Interface down.'
                         - 'up - Interface up.'
                        choices:
                            - 'down'
                            - 'up'
    schema_object1:
        methods: [get]
        description: 'Interface configuration.'
        api_categories: [api_tag0]
        api_tag0:
            fields:
                -
                    -
                        type: str
                        choices:
                            - 'alias'
                            - 'allowaccess'
                            - 'description'
                            - 'ip'
                            - 'mtu'
                            - 'name'
                            - 'serviceaccess'
                            - 'speed'
                            - 'status'
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
                 - 'syntax - Return the attribute syntax of a table or an object, instead of the actual entry data. All filter parameters will be ignored.'
                choices:
                    - 'count'
                    - 'syntax'

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

    - name: REQUESTING /CLI/SYSTEM/INTERFACE
      fmgr_system_interface:
         method: <value in [add, set, update]>
         params:
            -
               data:
                 -
                     alias: <value of string>
                     allowaccess:
                       - <value in [ping, https, ssh, ...]>
                     description: <value of string>
                     ip: <value of string default: '0.0.0.0 0.0.0.0'>
                     ipv6:
                        ip6-address: <value of string default: '::/0'>
                        ip6-allowaccess:
                          - <value in [ping, https, ssh, ...]>
                        ip6-autoconf: <value in [disable, enable] default: 'enable'>
                     mtu: <value of integer default: 1500>
                     name: <value of string>
                     serviceaccess:
                       - <value in [fgtupdates, fclupdates, webfilter-antispam]>
                     speed: <value in [auto, 10full, 10half, ...] default: 'auto'>
                     status: <value in [down, up] default: 'up'>

    - name: REQUESTING /CLI/SYSTEM/INTERFACE
      fmgr_system_interface:
         method: <value in [get]>
         params:
            -
               fields:
                 -
                    - <value in [alias, allowaccess, description, ...]>
               filter:
                 - <value of string>
               loadsub: <value of integer>
               option: <value in [count, syntax]>

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
            example: '/cli/global/system/interface'
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
               alias:
                  type: str
                  description: 'Alias.'
               allowaccess:
                  type: array
                  suboptions:
                     type: str
               description:
                  type: str
                  description: 'Description.'
               ip:
                  type: str
                  description: 'IP address of interface.'
                  example: '0.0.0.0 0.0.0.0'
               ipv6:
                  ip6-address:
                     type: str
                     description: 'IPv6 address/prefix of interface.'
                     example: '::/0'
                  ip6-allowaccess:
                     type: array
                     suboptions:
                        type: str
                  ip6-autoconf:
                     type: str
                     description: |
                        'Enable/disable address auto config (SLAAC).'
                        'disable - Disable setting.'
                        'enable - Enable setting.'
                     example: 'enable'
               mtu:
                  type: int
                  description: 'Maximum transportation unit(68 - 9000).'
                  example: 1500
               name:
                  type: str
                  description: 'Interface name.'
               serviceaccess:
                  type: array
                  suboptions:
                     type: str
               speed:
                  type: str
                  description: |
                     'Speed.'
                     'auto - Auto adjust speed.'
                     '10full - 10M full-duplex.'
                     '10half - 10M half-duplex.'
                     '100full - 100M full-duplex.'
                     '100half - 100M half-duplex.'
                     '1000full - 1000M full-duplex.'
                     '10000full - 10000M full-duplex.'
                  example: 'auto'
               status:
                  type: str
                  description: |
                     'Interface status.'
                     'down - Interface down.'
                     'up - Interface up.'
                  example: 'up'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/cli/global/system/interface'

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
        '/cli/global/system/interface'
    ]

    url_schema = [
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'alias': {
                            'type': 'string'
                        },
                        'allowaccess': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'ping',
                                    'https',
                                    'ssh',
                                    'snmp',
                                    'http',
                                    'webservice',
                                    'https-logging'
                                ]
                            }
                        },
                        'description': {
                            'type': 'string'
                        },
                        'ip': {
                            'type': 'string'
                        },
                        'ipv6': {
                            'ip6-address': {
                                'type': 'string'
                            },
                            'ip6-allowaccess': {
                                'type': 'array',
                                'items': {
                                    'type': 'string',
                                    'enum': [
                                        'ping',
                                        'https',
                                        'ssh',
                                        'snmp',
                                        'http',
                                        'webservice',
                                        'https-logging'
                                    ]
                                }
                            },
                            'ip6-autoconf': {
                                'type': 'string',
                                'enum': [
                                    'disable',
                                    'enable'
                                ]
                            }
                        },
                        'mtu': {
                            'type': 'integer',
                            'default': 1500,
                            'example': 1500
                        },
                        'name': {
                            'type': 'string'
                        },
                        'serviceaccess': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'fgtupdates',
                                    'fclupdates',
                                    'webfilter-antispam'
                                ]
                            }
                        },
                        'speed': {
                            'type': 'string',
                            'enum': [
                                'auto',
                                '10full',
                                '10half',
                                '100full',
                                '100half',
                                '1000full',
                                '10000full'
                            ]
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'down',
                                'up'
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
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'alias',
                                'allowaccess',
                                'description',
                                'ip',
                                'mtu',
                                'name',
                                'serviceaccess',
                                'speed',
                                'status'
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
                            'syntax'
                        ]
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
        'loose_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
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
