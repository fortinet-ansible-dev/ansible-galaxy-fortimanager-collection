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
module: fmgr_dnsfilter_profile
short_description: Configure DNS domain filter profiles.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/dnsfilter/profile
    - /pm/config/global/obj/dnsfilter/profile
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
        description: 'Configure DNS domain filter profiles.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    block-action:
                        type: str
                        description: 'Action to take for blocked domains.'
                        choices:
                            - 'block'
                            - 'redirect'
                    block-botnet:
                        type: str
                        description: 'Enable/disable blocking botnet C&C DNS lookups.'
                        choices:
                            - 'disable'
                            - 'enable'
                    comment:
                        type: str
                        description: 'Comment.'
                    external-ip-blocklist:
                        type: str
                        description: 'One or more external IP block lists.'
                    log-all-domain:
                        type: str
                        description: 'Enable/disable logging of all domains visited (detailed DNS logging).'
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: 'Profile name.'
                    redirect-portal:
                        type: str
                        description: 'IP address of the SDNS redirect portal.'
                    safe-search:
                        type: str
                        description: 'Enable/disable Google, Bing, and YouTube safe search.'
                        choices:
                            - 'disable'
                            - 'enable'
                    sdns-domain-log:
                        type: str
                        description: 'Enable/disable domain filtering and botnet domain logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    sdns-ftgd-err-log:
                        type: str
                        description: 'Enable/disable FortiGuard SDNS rating error logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    youtube-restrict:
                        type: str
                        description: 'Set safe search for YouTube restriction level.'
                        choices:
                            - 'strict'
                            - 'moderate'
    schema_object1:
        methods: [get]
        description: 'Configure DNS domain filter profiles.'
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
                            - 'block-action'
                            - 'block-botnet'
                            - 'comment'
                            - 'external-ip-blocklist'
                            - 'log-all-domain'
                            - 'name'
                            - 'redirect-portal'
                            - 'safe-search'
                            - 'sdns-domain-log'
                            - 'sdns-ftgd-err-log'
                            - 'youtube-restrict'
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

    - name: REQUESTING /PM/CONFIG/OBJ/DNSFILTER/PROFILE
      fmgr_dnsfilter_profile:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     block-action: <value in [block, redirect]>
                     block-botnet: <value in [disable, enable]>
                     comment: <value of string>
                     external-ip-blocklist: <value of string>
                     log-all-domain: <value in [disable, enable]>
                     name: <value of string>
                     redirect-portal: <value of string>
                     safe-search: <value in [disable, enable]>
                     sdns-domain-log: <value in [disable, enable]>
                     sdns-ftgd-err-log: <value in [disable, enable]>
                     youtube-restrict: <value in [strict, moderate]>

    - name: REQUESTING /PM/CONFIG/OBJ/DNSFILTER/PROFILE
      fmgr_dnsfilter_profile:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [block-action, block-botnet, comment, ...]>
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
            example: '/pm/config/adom/{adom}/obj/dnsfilter/profile'
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
               block-action:
                  type: str
                  description: 'Action to take for blocked domains.'
               block-botnet:
                  type: str
                  description: 'Enable/disable blocking botnet C&C DNS lookups.'
               comment:
                  type: str
                  description: 'Comment.'
               external-ip-blocklist:
                  type: str
                  description: 'One or more external IP block lists.'
               log-all-domain:
                  type: str
                  description: 'Enable/disable logging of all domains visited (detailed DNS logging).'
               name:
                  type: str
                  description: 'Profile name.'
               redirect-portal:
                  type: str
                  description: 'IP address of the SDNS redirect portal.'
               safe-search:
                  type: str
                  description: 'Enable/disable Google, Bing, and YouTube safe search.'
               sdns-domain-log:
                  type: str
                  description: 'Enable/disable domain filtering and botnet domain logging.'
               sdns-ftgd-err-log:
                  type: str
                  description: 'Enable/disable FortiGuard SDNS rating error logging.'
               youtube-restrict:
                  type: str
                  description: 'Set safe search for YouTube restriction level.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/dnsfilter/profile'

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
        '/pm/config/adom/{adom}/obj/dnsfilter/profile',
        '/pm/config/global/obj/dnsfilter/profile'
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
                        'block-action': {
                            'type': 'string',
                            'enum': [
                                'block',
                                'redirect'
                            ]
                        },
                        'block-botnet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'external-ip-blocklist': {
                            'type': 'string'
                        },
                        'log-all-domain': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        },
                        'redirect-portal': {
                            'type': 'string'
                        },
                        'safe-search': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'sdns-domain-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'sdns-ftgd-err-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'youtube-restrict': {
                            'type': 'string',
                            'enum': [
                                'strict',
                                'moderate'
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
                                'block-action',
                                'block-botnet',
                                'comment',
                                'external-ip-blocklist',
                                'log-all-domain',
                                'name',
                                'redirect-portal',
                                'safe-search',
                                'sdns-domain-log',
                                'sdns-ftgd-err-log',
                                'youtube-restrict'
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
