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
module: fmgr_devprof_system_emailserver
short_description: Configure the email server used by the FortiGate various things. For example, for sending email messages to users to support user authen...
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /pm/config/adom/{adom}/devprof/{devprof}/system/email-server
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
        description: 'Configure the email server used by the FortiGate various things. For example, for sending email messages to users to support user auth...'
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
        description: 'Configure the email server used by the FortiGate various things. For example, for sending email messages to users to support user auth...'
        api_categories: [api_tag0]
        api_tag0:
            data:
                authenticate:
                    type: str
                    description: 'Enable/disable authentication.'
                    choices:
                        - 'disable'
                        - 'enable'
                password:
                    -
                        type: str
                port:
                    type: int
                    description: 'SMTP server port.'
                reply-to:
                    type: str
                    description: 'Reply-To email address.'
                security:
                    type: str
                    description: 'Connection security used by the email server.'
                    choices:
                        - 'none'
                        - 'starttls'
                        - 'smtps'
                server:
                    type: str
                    description: 'SMTP server IP address or hostname.'
                source-ip:
                    type: str
                    description: 'SMTP server IPv4 source IP.'
                source-ip6:
                    type: str
                    description: 'SMTP server IPv6 source IP.'
                ssl-min-proto-version:
                    type: str
                    description: 'Minimum supported protocol version for SSL/TLS connections (default is to follow system global setting).'
                    choices:
                        - 'default'
                        - 'TLSv1'
                        - 'TLSv1-1'
                        - 'TLSv1-2'
                        - 'SSLv3'
                type:
                    type: str
                    description: 'Use FortiGuard Message service or custom email server.'
                    choices:
                        - 'custom'
                username:
                    type: str
                    description: 'SMTP server user name for authentication.'
                validate-server:
                    type: str
                    description: 'Enable/disable validation of server certificate.'
                    choices:
                        - 'disable'
                        - 'enable'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/EMAIL-SERVER
      fmgr_devprof_system_emailserver:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/EMAIL-SERVER
      fmgr_devprof_system_emailserver:
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               data:
                  authenticate: <value in [disable, enable]>
                  password:
                    - <value of string>
                  port: <value of integer>
                  reply-to: <value of string>
                  security: <value in [none, starttls, smtps]>
                  server: <value of string>
                  source-ip: <value of string>
                  source-ip6: <value of string>
                  ssl-min-proto-version: <value in [default, TLSv1, TLSv1-1, ...]>
                  type: <value in [custom]>
                  username: <value of string>
                  validate-server: <value in [disable, enable]>

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
            authenticate:
               type: str
               description: 'Enable/disable authentication.'
            password:
               type: array
               suboptions:
                  type: str
            port:
               type: int
               description: 'SMTP server port.'
            reply-to:
               type: str
               description: 'Reply-To email address.'
            security:
               type: str
               description: 'Connection security used by the email server.'
            server:
               type: str
               description: 'SMTP server IP address or hostname.'
            source-ip:
               type: str
               description: 'SMTP server IPv4 source IP.'
            source-ip6:
               type: str
               description: 'SMTP server IPv6 source IP.'
            ssl-min-proto-version:
               type: str
               description: 'Minimum supported protocol version for SSL/TLS connections (default is to follow system global setting).'
            type:
               type: str
               description: 'Use FortiGuard Message service or custom email server.'
            username:
               type: str
               description: 'SMTP server user name for authentication.'
            validate-server:
               type: str
               description: 'Enable/disable validation of server certificate.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'
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
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'
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
                        'authenticate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'password': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'port': {
                            'type': 'integer'
                        },
                        'reply-to': {
                            'type': 'string'
                        },
                        'security': {
                            'type': 'string',
                            'enum': [
                                'none',
                                'starttls',
                                'smtps'
                            ]
                        },
                        'server': {
                            'type': 'string'
                        },
                        'source-ip': {
                            'type': 'string'
                        },
                        'source-ip6': {
                            'type': 'string'
                        },
                        'ssl-min-proto-version': {
                            'type': 'string',
                            'enum': [
                                'default',
                                'TLSv1',
                                'TLSv1-1',
                                'TLSv1-2',
                                'SSLv3'
                            ]
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'custom'
                            ]
                        },
                        'username': {
                            'type': 'string'
                        },
                        'validate-server': {
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
