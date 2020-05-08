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
module: fmgr_devprof_log_syslogd_setting
short_description: Global settings for remote syslog server.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting
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
            devprof:
                type: str
    schema_object0:
        methods: [get]
        description: 'Global settings for remote syslog server.'
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
        description: 'Global settings for remote syslog server.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                certificate:
                    type: str
                    description: 'Certificate used to communicate with Syslog server.'
                enc-algorithm:
                    type: str
                    description: 'Enable/disable reliable syslogging with TLS encryption.'
                    choices:
                        - 'high'
                        - 'low'
                        - 'disable'
                        - 'high-medium'
                facility:
                    type: str
                    description: 'Remote syslog facility.'
                    choices:
                        - 'kernel'
                        - 'user'
                        - 'mail'
                        - 'daemon'
                        - 'auth'
                        - 'syslog'
                        - 'lpr'
                        - 'news'
                        - 'uucp'
                        - 'cron'
                        - 'authpriv'
                        - 'ftp'
                        - 'ntp'
                        - 'audit'
                        - 'alert'
                        - 'clock'
                        - 'local0'
                        - 'local1'
                        - 'local2'
                        - 'local3'
                        - 'local4'
                        - 'local5'
                        - 'local6'
                        - 'local7'
                mode:
                    type: str
                    description: 'Remote syslog logging over UDP/Reliable TCP.'
                    choices:
                        - 'udp'
                        - 'legacy-reliable'
                        - 'reliable'
                port:
                    type: int
                    description: 'Server listen port.'
                server:
                    type: str
                    description: 'Address of remote syslog server.'
                ssl-min-proto-version:
                    type: str
                    description: 'Minimum supported protocol version for SSL/TLS connections (default is to follow system global setting).'
                    choices:
                        - 'default'
                        - 'TLSv1-1'
                        - 'TLSv1-2'
                        - 'SSLv3'
                        - 'TLSv1'
                status:
                    type: str
                    description: 'Enable/disable remote syslog logging.'
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

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/LOG/SYSLOGD/SETTING
      fmgr_devprof_log_syslogd_setting:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/LOG/SYSLOGD/SETTING
      fmgr_devprof_log_syslogd_setting:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               data:
                  certificate: <value of string>
                  enc-algorithm: <value in [high, low, disable, ...]>
                  facility: <value in [kernel, user, mail, ...]>
                  mode: <value in [udp, legacy-reliable, reliable]>
                  port: <value of integer>
                  server: <value of string>
                  ssl-min-proto-version: <value in [default, TLSv1-1, TLSv1-2, ...]>
                  status: <value in [disable, enable]>

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
            certificate:
               type: str
               description: 'Certificate used to communicate with Syslog server.'
            enc-algorithm:
               type: str
               description: 'Enable/disable reliable syslogging with TLS encryption.'
            facility:
               type: str
               description: 'Remote syslog facility.'
            mode:
               type: str
               description: 'Remote syslog logging over UDP/Reliable TCP.'
            port:
               type: int
               description: 'Server listen port.'
            server:
               type: str
               description: 'Address of remote syslog server.'
            ssl-min-proto-version:
               type: str
               description: 'Minimum supported protocol version for SSL/TLS connections (default is to follow system global setting).'
            status:
               type: str
               description: 'Enable/disable remote syslog logging.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting'
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
            example: '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting'

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
        '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting'
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
                        'certificate': {
                            'type': 'string'
                        },
                        'enc-algorithm': {
                            'type': 'string',
                            'enum': [
                                'high',
                                'low',
                                'disable',
                                'high-medium'
                            ]
                        },
                        'facility': {
                            'type': 'string',
                            'enum': [
                                'kernel',
                                'user',
                                'mail',
                                'daemon',
                                'auth',
                                'syslog',
                                'lpr',
                                'news',
                                'uucp',
                                'cron',
                                'authpriv',
                                'ftp',
                                'ntp',
                                'audit',
                                'alert',
                                'clock',
                                'local0',
                                'local1',
                                'local2',
                                'local3',
                                'local4',
                                'local5',
                                'local6',
                                'local7'
                            ]
                        },
                        'mode': {
                            'type': 'string',
                            'enum': [
                                'udp',
                                'legacy-reliable',
                                'reliable'
                            ]
                        },
                        'port': {
                            'type': 'integer'
                        },
                        'server': {
                            'type': 'string'
                        },
                        'ssl-min-proto-version': {
                            'type': 'string',
                            'enum': [
                                'default',
                                'TLSv1-1',
                                'TLSv1-2',
                                'SSLv3',
                                'TLSv1'
                            ]
                        },
                        'status': {
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
