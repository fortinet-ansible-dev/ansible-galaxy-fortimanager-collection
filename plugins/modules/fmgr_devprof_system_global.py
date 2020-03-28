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
module: fmgr_devprof_system_global
short_description: Configure global attributes.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /pm/config/adom/{adom}/devprof/{devprof}/system/global
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
            devprof:
                type: str
    schema_object0:
        methods: [get]
        description: 'Configure global attributes.'
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
    schema_object1:
        methods: [set, update]
        description: 'Configure global attributes.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                admin-https-redirect:
                    type: str
                    description: 'Enable/disable redirection of HTTP administration access to HTTPS.'
                    choices:
                        - 'disable'
                        - 'enable'
                admin-port:
                    type: int
                    description: 'Administrative access port for HTTP. (1 - 65535, default = 80).'
                admin-scp:
                    type: str
                    description: 'Enable/disable using SCP to download the system configuration. You can use SCP as an alternative method for backing up the...'
                    choices:
                        - 'disable'
                        - 'enable'
                admin-sport:
                    type: int
                    description: 'Administrative access port for HTTPS. (1 - 65535, default = 443).'
                admin-ssh-port:
                    type: int
                    description: 'Administrative access port for SSH. (1 - 65535, default = 22).'
                admin-ssh-v1:
                    type: str
                    description: 'Enable/disable SSH v1 compatibility.'
                    choices:
                        - 'disable'
                        - 'enable'
                admin-telnet-port:
                    type: int
                    description: 'Administrative access port for TELNET. (1 - 65535, default = 23).'
                admintimeout:
                    type: int
                    description: 'Number of minutes before an idle administrator session times out (5 - 480 minutes (8 hours), default = 5). A shorter idle ...'
                gui-ipv6:
                    type: str
                    description: 'Enable/disable IPv6 settings on the GUI.'
                    choices:
                        - 'disable'
                        - 'enable'
                gui-lines-per-page:
                    type: int
                    description: 'Number of lines to display per page for web administration.'
                gui-theme:
                    type: str
                    description: 'Color scheme for the administration GUI.'
                    choices:
                        - 'blue'
                        - 'green'
                        - 'melongene'
                        - 'red'
                        - 'mariner'
                language:
                    type: str
                    description: 'GUI display language.'
                    choices:
                        - 'english'
                        - 'simch'
                        - 'japanese'
                        - 'korean'
                        - 'spanish'
                        - 'trach'
                        - 'french'
                        - 'portuguese'
                switch-controller:
                    type: str
                    description: 'Enable/disable switch controller feature. Switch controller allows you to manage FortiSwitch from the FortiGate itself.'
                    choices:
                        - 'disable'
                        - 'enable'

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

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/GLOBAL
      fmgr_devprof_system_global:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/GLOBAL
      fmgr_devprof_system_global:
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               data:
                  admin-https-redirect: <value in [disable, enable]>
                  admin-port: <value of integer>
                  admin-scp: <value in [disable, enable]>
                  admin-sport: <value of integer>
                  admin-ssh-port: <value of integer>
                  admin-ssh-v1: <value in [disable, enable]>
                  admin-telnet-port: <value of integer>
                  admintimeout: <value of integer>
                  gui-ipv6: <value in [disable, enable]>
                  gui-lines-per-page: <value of integer>
                  gui-theme: <value in [blue, green, melongene, ...]>
                  language: <value in [english, simch, japanese, ...]>
                  switch-controller: <value in [disable, enable]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            admin-https-redirect:
               type: str
               description: 'Enable/disable redirection of HTTP administration access to HTTPS.'
            admin-port:
               type: int
               description: 'Administrative access port for HTTP. (1 - 65535, default = 80).'
            admin-scp:
               type: str
               description: 'Enable/disable using SCP to download the system configuration. You can use SCP as an alternative method for backing up the conf...'
            admin-sport:
               type: int
               description: 'Administrative access port for HTTPS. (1 - 65535, default = 443).'
            admin-ssh-port:
               type: int
               description: 'Administrative access port for SSH. (1 - 65535, default = 22).'
            admin-ssh-v1:
               type: str
               description: 'Enable/disable SSH v1 compatibility.'
            admin-telnet-port:
               type: int
               description: 'Administrative access port for TELNET. (1 - 65535, default = 23).'
            admintimeout:
               type: int
               description: 'Number of minutes before an idle administrator session times out (5 - 480 minutes (8 hours), default = 5). A shorter idle timeo...'
            gui-ipv6:
               type: str
               description: 'Enable/disable IPv6 settings on the GUI.'
            gui-lines-per-page:
               type: int
               description: 'Number of lines to display per page for web administration.'
            gui-theme:
               type: str
               description: 'Color scheme for the administration GUI.'
            language:
               type: str
               description: 'GUI display language.'
            switch-controller:
               type: str
               description: 'Enable/disable switch controller feature. Switch controller allows you to manage FortiSwitch from the FortiGate itself.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
return_of_api_category_0:
   description: items returned for method:[set, update]
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
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/global'

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'devprof',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
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
            ],
            'object1': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'admin-https-redirect': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'admin-port': {
                            'type': 'integer'
                        },
                        'admin-scp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'admin-sport': {
                            'type': 'integer'
                        },
                        'admin-ssh-port': {
                            'type': 'integer'
                        },
                        'admin-ssh-v1': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'admin-telnet-port': {
                            'type': 'integer'
                        },
                        'admintimeout': {
                            'type': 'integer'
                        },
                        'gui-ipv6': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'gui-lines-per-page': {
                            'type': 'integer'
                        },
                        'gui-theme': {
                            'type': 'string',
                            'enum': [
                                'blue',
                                'green',
                                'melongene',
                                'red',
                                'mariner'
                            ]
                        },
                        'language': {
                            'type': 'string',
                            'enum': [
                                'english',
                                'simch',
                                'japanese',
                                'korean',
                                'spanish',
                                'trach',
                                'french',
                                'portuguese'
                            ]
                        },
                        'switch-controller': {
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
            ]
        },
        'method_mapping': {
            'get': 'object0',
            'set': 'object1',
            'update': 'object1'
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
