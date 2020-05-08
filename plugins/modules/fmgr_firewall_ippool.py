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
module: fmgr_firewall_ippool
short_description: Configure IPv4 IP pools.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/ippool
    - /pm/config/global/obj/firewall/ippool
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
    schema_object0:
        methods: [add, set, update]
        description: 'Configure IPv4 IP pools.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    arp-intf:
                        type: str
                        description: 'Select an interface from available options that will reply to ARP requests. (If blank, any is selected).'
                    arp-reply:
                        type: str
                        description: 'Enable/disable replying to ARP requests when an IP Pool is added to a policy (default = enable).'
                        choices:
                            - 'disable'
                            - 'enable'
                    associated-interface:
                        type: str
                        description: 'Associated interface name.'
                    block-size:
                        type: int
                        description: 'Number of addresses in a block (64 to 4096, default = 128).'
                    comments:
                        type: str
                        description: 'Comment.'
                    dynamic_mapping:
                        -
                            _scope:
                                -
                                    name:
                                        type: str
                                    vdom:
                                        type: str
                            arp-intf:
                                type: str
                            arp-reply:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            associated-interface:
                                type: str
                            block-size:
                                type: int
                            comments:
                                type: str
                            endip:
                                type: str
                            num-blocks-per-user:
                                type: int
                            pba-timeout:
                                type: int
                            permit-any-host:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            source-endip:
                                type: str
                            source-startip:
                                type: str
                            startip:
                                type: str
                            type:
                                type: str
                                choices:
                                    - 'overload'
                                    - 'one-to-one'
                                    - 'fixed-port-range'
                                    - 'port-block-allocation'
                    endip:
                        type: str
                        description: 'Final IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
                    name:
                        type: str
                        description: 'IP pool name.'
                    num-blocks-per-user:
                        type: int
                        description: 'Number of addresses blocks that can be used by a user (1 to 128, default = 8).'
                    pba-timeout:
                        type: int
                        description: 'Port block allocation timeout (seconds).'
                    permit-any-host:
                        type: str
                        description: 'Enable/disable full cone NAT.'
                        choices:
                            - 'disable'
                            - 'enable'
                    source-endip:
                        type: str
                        description: 'Final IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default:...'
                    source-startip:
                        type: str
                        description: 'First IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default:...'
                    startip:
                        type: str
                        description: 'First IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
                    type:
                        type: str
                        description: 'IP pool type (overload, one-to-one, fixed port range, or port block allocation).'
                        choices:
                            - 'overload'
                            - 'one-to-one'
                            - 'fixed-port-range'
                            - 'port-block-allocation'
    schema_object1:
        methods: [get]
        description: 'Configure IPv4 IP pools.'
        api_categories: [api_tag0]
        api_tag0:
            attr:
                type: str
                description: 'The name of the attribute to retrieve its datasource. Only used with &lt;i&gt;datasrc&lt;/i&gt; option.'
            fields:
                -
                    -
                        type: str
                        choices:
                            - 'arp-intf'
                            - 'arp-reply'
                            - 'associated-interface'
                            - 'block-size'
                            - 'comments'
                            - 'endip'
                            - 'name'
                            - 'num-blocks-per-user'
                            - 'pba-timeout'
                            - 'permit-any-host'
                            - 'source-endip'
                            - 'source-startip'
                            - 'startip'
                            - 'type'
            filter:
                -
                    type: str
            get used:
                type: int
            loadsub:
                type: int
                description: 'Enable or disable the return of any sub-objects. If not specified, the default is to return all sub-objects.'
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.'
                 - 'count - Return the number of matching entries instead of the actual entry data.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'datasrc - Return all objects that can be referenced by an attribute. Require <i>attr</i> parameter.'
                 - 'get reserved - Also return reserved objects in the result.'
                 - 'syntax - Return the attribute syntax of a table or an object, instead of the actual entry data. All filter parameters will be ignored.'
                choices:
                    - 'count'
                    - 'object member'
                    - 'datasrc'
                    - 'get reserved'
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
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/IPPOOL
      fmgr_firewall_ippool:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     arp-intf: <value of string>
                     arp-reply: <value in [disable, enable]>
                     associated-interface: <value of string>
                     block-size: <value of integer>
                     comments: <value of string>
                     dynamic_mapping:
                       -
                           _scope:
                             -
                                 name: <value of string>
                                 vdom: <value of string>
                           arp-intf: <value of string>
                           arp-reply: <value in [disable, enable]>
                           associated-interface: <value of string>
                           block-size: <value of integer>
                           comments: <value of string>
                           endip: <value of string>
                           num-blocks-per-user: <value of integer>
                           pba-timeout: <value of integer>
                           permit-any-host: <value in [disable, enable]>
                           source-endip: <value of string>
                           source-startip: <value of string>
                           startip: <value of string>
                           type: <value in [overload, one-to-one, fixed-port-range, ...]>
                     endip: <value of string>
                     name: <value of string>
                     num-blocks-per-user: <value of integer>
                     pba-timeout: <value of integer>
                     permit-any-host: <value in [disable, enable]>
                     source-endip: <value of string>
                     source-startip: <value of string>
                     startip: <value of string>
                     type: <value in [overload, one-to-one, fixed-port-range, ...]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/IPPOOL
      fmgr_firewall_ippool:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [arp-intf, arp-reply, associated-interface, ...]>
               filter:
                 - <value of string>
               get used: <value of integer>
               loadsub: <value of integer>
               option: <value in [count, object member, datasrc, ...]>
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
            example: '/pm/config/adom/{adom}/obj/firewall/ippool'
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
               arp-intf:
                  type: str
                  description: 'Select an interface from available options that will reply to ARP requests. (If blank, any is selected).'
               arp-reply:
                  type: str
                  description: 'Enable/disable replying to ARP requests when an IP Pool is added to a policy (default = enable).'
               associated-interface:
                  type: str
                  description: 'Associated interface name.'
               block-size:
                  type: int
                  description: 'Number of addresses in a block (64 to 4096, default = 128).'
               comments:
                  type: str
                  description: 'Comment.'
               dynamic_mapping:
                  type: array
                  suboptions:
                     _scope:
                        type: array
                        suboptions:
                           name:
                              type: str
                           vdom:
                              type: str
                     arp-intf:
                        type: str
                     arp-reply:
                        type: str
                     associated-interface:
                        type: str
                     block-size:
                        type: int
                     comments:
                        type: str
                     endip:
                        type: str
                     num-blocks-per-user:
                        type: int
                     pba-timeout:
                        type: int
                     permit-any-host:
                        type: str
                     source-endip:
                        type: str
                     source-startip:
                        type: str
                     startip:
                        type: str
                     type:
                        type: str
               endip:
                  type: str
                  description: 'Final IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
               name:
                  type: str
                  description: 'IP pool name.'
               num-blocks-per-user:
                  type: int
                  description: 'Number of addresses blocks that can be used by a user (1 to 128, default = 8).'
               pba-timeout:
                  type: int
                  description: 'Port block allocation timeout (seconds).'
               permit-any-host:
                  type: str
                  description: 'Enable/disable full cone NAT.'
               source-endip:
                  type: str
                  description: 'Final IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default: 0.0.0...'
               source-startip:
                  type: str
                  description: 'First IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx, Default: 0.0.0...'
               startip:
                  type: str
                  description: 'First IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).'
               type:
                  type: str
                  description: 'IP pool type (overload, one-to-one, fixed port range, or port block allocation).'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/ippool'

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
        '/pm/config/adom/{adom}/obj/firewall/ippool',
        '/pm/config/global/obj/firewall/ippool'
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
                        'arp-intf': {
                            'type': 'string'
                        },
                        'arp-reply': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'associated-interface': {
                            'type': 'string'
                        },
                        'block-size': {
                            'type': 'integer'
                        },
                        'comments': {
                            'type': 'string'
                        },
                        'dynamic_mapping': {
                            'type': 'array',
                            'items': {
                                '_scope': {
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
                                'arp-intf': {
                                    'type': 'string'
                                },
                                'arp-reply': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'associated-interface': {
                                    'type': 'string'
                                },
                                'block-size': {
                                    'type': 'integer'
                                },
                                'comments': {
                                    'type': 'string'
                                },
                                'endip': {
                                    'type': 'string'
                                },
                                'num-blocks-per-user': {
                                    'type': 'integer'
                                },
                                'pba-timeout': {
                                    'type': 'integer'
                                },
                                'permit-any-host': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'source-endip': {
                                    'type': 'string'
                                },
                                'source-startip': {
                                    'type': 'string'
                                },
                                'startip': {
                                    'type': 'string'
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
                                        'overload',
                                        'one-to-one',
                                        'fixed-port-range',
                                        'port-block-allocation'
                                    ]
                                }
                            }
                        },
                        'endip': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'num-blocks-per-user': {
                            'type': 'integer'
                        },
                        'pba-timeout': {
                            'type': 'integer'
                        },
                        'permit-any-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'source-endip': {
                            'type': 'string'
                        },
                        'source-startip': {
                            'type': 'string'
                        },
                        'startip': {
                            'type': 'string'
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'overload',
                                'one-to-one',
                                'fixed-port-range',
                                'port-block-allocation'
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
                    'name': 'attr',
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
                                'arp-intf',
                                'arp-reply',
                                'associated-interface',
                                'block-size',
                                'comments',
                                'endip',
                                'name',
                                'num-blocks-per-user',
                                'pba-timeout',
                                'permit-any-host',
                                'source-endip',
                                'source-startip',
                                'startip',
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
                    'name': 'get used',
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
                            'datasrc',
                            'get reserved',
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
