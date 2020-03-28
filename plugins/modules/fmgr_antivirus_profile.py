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
module: fmgr_antivirus_profile
short_description: Configure AntiVirus profiles.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/antivirus/profile
    - /pm/config/global/obj/antivirus/profile
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
        description: 'Configure AntiVirus profiles.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    analytics-bl-filetype:
                        type: str
                        description: 'Only submit files matching this DLP file-pattern to FortiSandbox.'
                    analytics-db:
                        type: str
                        description: 'Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.'
                        choices:
                            - 'disable'
                            - 'enable'
                    analytics-max-upload:
                        type: int
                        description: 'Maximum size of files that can be uploaded to FortiSandbox (1 - 395 MBytes, default = 10).'
                    analytics-wl-filetype:
                        type: str
                        description: 'Do not submit files matching this DLP file-pattern to FortiSandbox.'
                    av-block-log:
                        type: str
                        description: 'Enable/disable logging for AntiVirus file blocking.'
                        choices:
                            - 'disable'
                            - 'enable'
                    av-virus-log:
                        type: str
                        description: 'Enable/disable AntiVirus logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    comment:
                        type: str
                        description: 'Comment.'
                    extended-log:
                        type: str
                        description: 'Enable/disable extended logging for antivirus.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd-analytics:
                        type: str
                        description: 'Settings to control which files are uploaded to FortiSandbox.'
                        choices:
                            - 'disable'
                            - 'suspicious'
                            - 'everything'
                    inspection-mode:
                        type: str
                        description: 'Inspection mode.'
                        choices:
                            - 'proxy'
                            - 'flow-based'
                    mobile-malware-db:
                        type: str
                        description: 'Enable/disable using the mobile malware signature database.'
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: 'Profile name.'
                    replacemsg-group:
                        type: str
                        description: 'Replacement message group customized for this profile.'
                    scan-mode:
                        type: str
                        description: 'Choose between full scan mode and quick scan mode.'
                        choices:
                            - 'quick'
                            - 'full'
    schema_object1:
        methods: [get]
        description: 'Configure AntiVirus profiles.'
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
                            - 'analytics-bl-filetype'
                            - 'analytics-db'
                            - 'analytics-max-upload'
                            - 'analytics-wl-filetype'
                            - 'av-block-log'
                            - 'av-virus-log'
                            - 'comment'
                            - 'extended-log'
                            - 'ftgd-analytics'
                            - 'inspection-mode'
                            - 'mobile-malware-db'
                            - 'name'
                            - 'replacemsg-group'
                            - 'scan-mode'
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

    - name: REQUESTING /PM/CONFIG/OBJ/ANTIVIRUS/PROFILE
      fmgr_antivirus_profile:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     analytics-bl-filetype: <value of string>
                     analytics-db: <value in [disable, enable]>
                     analytics-max-upload: <value of integer>
                     analytics-wl-filetype: <value of string>
                     av-block-log: <value in [disable, enable]>
                     av-virus-log: <value in [disable, enable]>
                     comment: <value of string>
                     extended-log: <value in [disable, enable]>
                     ftgd-analytics: <value in [disable, suspicious, everything]>
                     inspection-mode: <value in [proxy, flow-based]>
                     mobile-malware-db: <value in [disable, enable]>
                     name: <value of string>
                     replacemsg-group: <value of string>
                     scan-mode: <value in [quick, full]>

    - name: REQUESTING /PM/CONFIG/OBJ/ANTIVIRUS/PROFILE
      fmgr_antivirus_profile:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [analytics-bl-filetype, analytics-db, analytics-max-upload, ...]>
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
            example: '/pm/config/adom/{adom}/obj/antivirus/profile'
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
               analytics-bl-filetype:
                  type: str
                  description: 'Only submit files matching this DLP file-pattern to FortiSandbox.'
               analytics-db:
                  type: str
                  description: 'Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.'
               analytics-max-upload:
                  type: int
                  description: 'Maximum size of files that can be uploaded to FortiSandbox (1 - 395 MBytes, default = 10).'
               analytics-wl-filetype:
                  type: str
                  description: 'Do not submit files matching this DLP file-pattern to FortiSandbox.'
               av-block-log:
                  type: str
                  description: 'Enable/disable logging for AntiVirus file blocking.'
               av-virus-log:
                  type: str
                  description: 'Enable/disable AntiVirus logging.'
               comment:
                  type: str
                  description: 'Comment.'
               extended-log:
                  type: str
                  description: 'Enable/disable extended logging for antivirus.'
               ftgd-analytics:
                  type: str
                  description: 'Settings to control which files are uploaded to FortiSandbox.'
               inspection-mode:
                  type: str
                  description: 'Inspection mode.'
               mobile-malware-db:
                  type: str
                  description: 'Enable/disable using the mobile malware signature database.'
               name:
                  type: str
                  description: 'Profile name.'
               replacemsg-group:
                  type: str
                  description: 'Replacement message group customized for this profile.'
               scan-mode:
                  type: str
                  description: 'Choose between full scan mode and quick scan mode.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/antivirus/profile'

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
        '/pm/config/adom/{adom}/obj/antivirus/profile',
        '/pm/config/global/obj/antivirus/profile'
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
                        'analytics-bl-filetype': {
                            'type': 'string'
                        },
                        'analytics-db': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'analytics-max-upload': {
                            'type': 'integer'
                        },
                        'analytics-wl-filetype': {
                            'type': 'string'
                        },
                        'av-block-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'av-virus-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'extended-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ftgd-analytics': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'suspicious',
                                'everything'
                            ]
                        },
                        'inspection-mode': {
                            'type': 'string',
                            'enum': [
                                'proxy',
                                'flow-based'
                            ]
                        },
                        'mobile-malware-db': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        },
                        'replacemsg-group': {
                            'type': 'string'
                        },
                        'scan-mode': {
                            'type': 'string',
                            'enum': [
                                'quick',
                                'full'
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
                                'analytics-bl-filetype',
                                'analytics-db',
                                'analytics-max-upload',
                                'analytics-wl-filetype',
                                'av-block-log',
                                'av-virus-log',
                                'comment',
                                'extended-log',
                                'ftgd-analytics',
                                'inspection-mode',
                                'mobile-malware-db',
                                'name',
                                'replacemsg-group',
                                'scan-mode'
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
