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
module: fmgr_firewall_sslsshprofile_obj
short_description: Configure SSL/SSH protocol options.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}
    - /pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}
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
            ssl-ssh-profile:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'Configure SSL/SSH protocol options.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                caname:
                    type: str
                    description: 'CA certificate used by SSL Inspection.'
                comment:
                    type: str
                    description: 'Optional comments.'
                mapi-over-https:
                    type: str
                    description: 'Enable/disable inspection of MAPI over HTTPS.'
                    choices:
                        - 'disable'
                        - 'enable'
                name:
                    type: str
                    description: 'Name.'
                rpc-over-https:
                    type: str
                    description: 'Enable/disable inspection of RPC over HTTPS.'
                    choices:
                        - 'disable'
                        - 'enable'
                server-cert:
                    type: str
                    description: 'Certificate used by SSL Inspection to replace server certificate.'
                server-cert-mode:
                    type: str
                    description: 'Re-sign or replace the servers certificate.'
                    choices:
                        - 're-sign'
                        - 'replace'
                ssl-anomalies-log:
                    type: str
                    description: 'Enable/disable logging SSL anomalies.'
                    choices:
                        - 'disable'
                        - 'enable'
                ssl-exempt:
                    -
                        address:
                            type: str
                            description: 'IPv4 address object.'
                        address6:
                            type: str
                            description: 'IPv6 address object.'
                        fortiguard-category:
                            type: str
                            description: 'FortiGuard category ID.'
                        id:
                            type: int
                            description: 'ID number.'
                        regex:
                            type: str
                            description: 'Exempt servers by regular expression.'
                        type:
                            type: str
                            description: 'Type of address object (IPv4 or IPv6) or FortiGuard category.'
                            choices:
                                - 'fortiguard-category'
                                - 'address'
                                - 'address6'
                                - 'wildcard-fqdn'
                                - 'regex'
                        wildcard-fqdn:
                            type: str
                            description: 'Exempt servers by wildcard FQDN.'
                ssl-exemptions-log:
                    type: str
                    description: 'Enable/disable logging SSL exemptions.'
                    choices:
                        - 'disable'
                        - 'enable'
                ssl-server:
                    -
                        ftps-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during the FTPS handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                        https-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during the HTTPS handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                        id:
                            type: int
                            description: 'SSL server ID.'
                        imaps-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during the IMAPS handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                        ip:
                            type: str
                            description: 'IPv4 address of the SSL server.'
                        pop3s-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during the POP3S handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                        smtps-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during the SMTPS handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                        ssl-other-client-cert-request:
                            type: str
                            description: 'Action based on client certificate request during an SSL protocol handshake.'
                            choices:
                                - 'bypass'
                                - 'inspect'
                                - 'block'
                untrusted-caname:
                    type: str
                    description: 'Untrusted CA certificate used by SSL Inspection.'
                use-ssl-server:
                    type: str
                    description: 'Enable/disable the use of SSL server table for SSL offloading.'
                    choices:
                        - 'disable'
                        - 'enable'
                whitelist:
                    type: str
                    description: 'Enable/disable exempting servers by FortiGuard whitelist.'
                    choices:
                        - 'disable'
                        - 'enable'
    schema_object1:
        methods: [delete]
        description: 'Configure SSL/SSH protocol options.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'Configure SSL/SSH protocol options.'
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

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/SSL-SSH-PROFILE/{SSL-SSH-PROFILE}
      fmgr_firewall_sslsshprofile_obj:
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            ssl-ssh-profile: <value of string>
         params:
            -
               data:
                  caname: <value of string>
                  comment: <value of string>
                  mapi-over-https: <value in [disable, enable]>
                  name: <value of string>
                  rpc-over-https: <value in [disable, enable]>
                  server-cert: <value of string>
                  server-cert-mode: <value in [re-sign, replace]>
                  ssl-anomalies-log: <value in [disable, enable]>
                  ssl-exempt:
                    -
                        address: <value of string>
                        address6: <value of string>
                        fortiguard-category: <value of string>
                        id: <value of integer>
                        regex: <value of string>
                        type: <value in [fortiguard-category, address, address6, ...]>
                        wildcard-fqdn: <value of string>
                  ssl-exemptions-log: <value in [disable, enable]>
                  ssl-server:
                    -
                        ftps-client-cert-request: <value in [bypass, inspect, block]>
                        https-client-cert-request: <value in [bypass, inspect, block]>
                        id: <value of integer>
                        imaps-client-cert-request: <value in [bypass, inspect, block]>
                        ip: <value of string>
                        pop3s-client-cert-request: <value in [bypass, inspect, block]>
                        smtps-client-cert-request: <value in [bypass, inspect, block]>
                        ssl-other-client-cert-request: <value in [bypass, inspect, block]>
                  untrusted-caname: <value of string>
                  use-ssl-server: <value in [disable, enable]>
                  whitelist: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/SSL-SSH-PROFILE/{SSL-SSH-PROFILE}
      fmgr_firewall_sslsshprofile_obj:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            ssl-ssh-profile: <value of string>
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
            example: '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            caname:
               type: str
               description: 'CA certificate used by SSL Inspection.'
            comment:
               type: str
               description: 'Optional comments.'
            mapi-over-https:
               type: str
               description: 'Enable/disable inspection of MAPI over HTTPS.'
            name:
               type: str
               description: 'Name.'
            rpc-over-https:
               type: str
               description: 'Enable/disable inspection of RPC over HTTPS.'
            server-cert:
               type: str
               description: 'Certificate used by SSL Inspection to replace server certificate.'
            server-cert-mode:
               type: str
               description: 'Re-sign or replace the servers certificate.'
            ssl-anomalies-log:
               type: str
               description: 'Enable/disable logging SSL anomalies.'
            ssl-exempt:
               type: array
               suboptions:
                  address:
                     type: str
                     description: 'IPv4 address object.'
                  address6:
                     type: str
                     description: 'IPv6 address object.'
                  fortiguard-category:
                     type: str
                     description: 'FortiGuard category ID.'
                  id:
                     type: int
                     description: 'ID number.'
                  regex:
                     type: str
                     description: 'Exempt servers by regular expression.'
                  type:
                     type: str
                     description: 'Type of address object (IPv4 or IPv6) or FortiGuard category.'
                  wildcard-fqdn:
                     type: str
                     description: 'Exempt servers by wildcard FQDN.'
            ssl-exemptions-log:
               type: str
               description: 'Enable/disable logging SSL exemptions.'
            ssl-server:
               type: array
               suboptions:
                  ftps-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during the FTPS handshake.'
                  https-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during the HTTPS handshake.'
                  id:
                     type: int
                     description: 'SSL server ID.'
                  imaps-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during the IMAPS handshake.'
                  ip:
                     type: str
                     description: 'IPv4 address of the SSL server.'
                  pop3s-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during the POP3S handshake.'
                  smtps-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during the SMTPS handshake.'
                  ssl-other-client-cert-request:
                     type: str
                     description: 'Action based on client certificate request during an SSL protocol handshake.'
            untrusted-caname:
               type: str
               description: 'Untrusted CA certificate used by SSL Inspection.'
            use-ssl-server:
               type: str
               description: 'Enable/disable the use of SSL server table for SSL offloading.'
            whitelist:
               type: str
               description: 'Enable/disable exempting servers by FortiGuard whitelist.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'

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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'ssl-ssh-profile',
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
                        'caname': {
                            'type': 'string'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'mapi-over-https': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        },
                        'rpc-over-https': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'server-cert': {
                            'type': 'string'
                        },
                        'server-cert-mode': {
                            'type': 'string',
                            'enum': [
                                're-sign',
                                'replace'
                            ]
                        },
                        'ssl-anomalies-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-exempt': {
                            'type': 'array',
                            'items': {
                                'address': {
                                    'type': 'string'
                                },
                                'address6': {
                                    'type': 'string'
                                },
                                'fortiguard-category': {
                                    'type': 'string'
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'regex': {
                                    'type': 'string'
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
                                        'fortiguard-category',
                                        'address',
                                        'address6',
                                        'wildcard-fqdn',
                                        'regex'
                                    ]
                                },
                                'wildcard-fqdn': {
                                    'type': 'string'
                                }
                            }
                        },
                        'ssl-exemptions-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-server': {
                            'type': 'array',
                            'items': {
                                'ftps-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                },
                                'https-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'imaps-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                },
                                'ip': {
                                    'type': 'string'
                                },
                                'pop3s-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                },
                                'smtps-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                },
                                'ssl-other-client-cert-request': {
                                    'type': 'string',
                                    'enum': [
                                        'bypass',
                                        'inspect',
                                        'block'
                                    ]
                                }
                            }
                        },
                        'untrusted-caname': {
                            'type': 'string'
                        },
                        'use-ssl-server': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'whitelist': {
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
