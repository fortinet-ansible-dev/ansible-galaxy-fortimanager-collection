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
module: fmgr_firewall_multicastaddress_obj
short_description: Configure multicast addresses.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}
    - /pm/config/global/obj/firewall/multicast-address/{multicast-address}
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
            multicast-address:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'Configure multicast addresses.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                associated-interface:
                    type: str
                    description: 'Interface associated with the address object. When setting up a policy, only addresses associated with this interface are ...'
                color:
                    type: int
                    description: 'Integer value to determine the color of the icon in the GUI (1 - 32, default = 0, which sets value to 1).'
                comment:
                    type: str
                    description: 'Comment.'
                end-ip:
                    type: str
                    description: 'Final IPv4 address (inclusive) in the range for the address.'
                name:
                    type: str
                    description: 'Multicast address name.'
                start-ip:
                    type: str
                    description: 'First IPv4 address (inclusive) in the range for the address.'
                subnet:
                    type: str
                    description: 'Broadcast address and subnet.'
                tagging:
                    -
                        category:
                            type: str
                            description: 'Tag category.'
                        name:
                            type: str
                            description: 'Tagging entry name.'
                        tags:
                            -
                                type: str
                type:
                    type: str
                    description: 'Type of address object: multicast IP address range or broadcast IP/mask to be treated as a multicast address.'
                    choices:
                        - 'multicastrange'
                        - 'broadcastmask'
                visibility:
                    type: str
                    description: 'Enable/disable visibility of the multicast address on the GUI.'
                    choices:
                        - 'disable'
                        - 'enable'
    schema_object1:
        methods: [delete]
        description: 'Configure multicast addresses.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'Configure multicast addresses.'
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
                    - 'datasrc'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/MULTICAST-ADDRESS/{MULTICAST-ADDRESS}
      fmgr_firewall_multicastaddress_obj:
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            multicast-address: <value of string>
         params:
            -
               data:
                  associated-interface: <value of string>
                  color: <value of integer>
                  comment: <value of string>
                  end-ip: <value of string>
                  name: <value of string>
                  start-ip: <value of string>
                  subnet: <value of string>
                  tagging:
                    -
                        category: <value of string>
                        name: <value of string>
                        tags:
                          - <value of string>
                  type: <value in [multicastrange, broadcastmask]>
                  visibility: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/MULTICAST-ADDRESS/{MULTICAST-ADDRESS}
      fmgr_firewall_multicastaddress_obj:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            multicast-address: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, delete, set, update]
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
            example: '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            associated-interface:
               type: str
               description: 'Interface associated with the address object. When setting up a policy, only addresses associated with this interface are avail...'
            color:
               type: int
               description: 'Integer value to determine the color of the icon in the GUI (1 - 32, default = 0, which sets value to 1).'
            comment:
               type: str
               description: 'Comment.'
            end-ip:
               type: str
               description: 'Final IPv4 address (inclusive) in the range for the address.'
            name:
               type: str
               description: 'Multicast address name.'
            start-ip:
               type: str
               description: 'First IPv4 address (inclusive) in the range for the address.'
            subnet:
               type: str
               description: 'Broadcast address and subnet.'
            tagging:
               type: array
               suboptions:
                  category:
                     type: str
                     description: 'Tag category.'
                  name:
                     type: str
                     description: 'Tagging entry name.'
                  tags:
                     type: array
                     suboptions:
                        type: str
            type:
               type: str
               description: 'Type of address object: multicast IP address range or broadcast IP/mask to be treated as a multicast address.'
            visibility:
               type: str
               description: 'Enable/disable visibility of the multicast address on the GUI.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}'

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
        '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
        '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'multicast-address',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'associated-interface': {
                            'type': 'string'
                        },
                        'color': {
                            'type': 'integer'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'end-ip': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'start-ip': {
                            'type': 'string'
                        },
                        'subnet': {
                            'type': 'string'
                        },
                        'tagging': {
                            'type': 'array',
                            'items': {
                                'category': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'tags': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                }
                            }
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'multicastrange',
                                'broadcastmask'
                            ]
                        },
                        'visibility': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
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
            ],
            'object1': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object2': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'object member',
                            'chksum',
                            'datasrc'
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
            'clone': 'object0',
            'delete': 'object1',
            'get': 'object2',
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
                'clone',
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
