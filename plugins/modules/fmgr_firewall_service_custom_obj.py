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
module: fmgr_firewall_service_custom_obj
short_description: Configure custom services.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get move set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/service/custom/{custom}
    - /pm/config/global/obj/firewall/service/custom/{custom}
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
            custom:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'Configure custom services.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                app-category:
                    -
                        type: int
                app-service-type:
                    type: str
                    description: 'Application service type.'
                    choices:
                        - 'disable'
                        - 'app-id'
                        - 'app-category'
                application:
                    -
                        type: int
                category:
                    type: str
                    description: 'Service category.'
                check-reset-range:
                    type: str
                    description: 'Configure the type of ICMP error message verification.'
                    choices:
                        - 'disable'
                        - 'default'
                        - 'strict'
                color:
                    type: int
                    description: 'Color of icon on the GUI.'
                comment:
                    type: str
                fqdn:
                    type: str
                    description: 'Fully qualified domain name.'
                helper:
                    type: str
                    description: 'Helper name.'
                    choices:
                        - 'disable'
                        - 'auto'
                        - 'ftp'
                        - 'tftp'
                        - 'ras'
                        - 'h323'
                        - 'tns'
                        - 'mms'
                        - 'sip'
                        - 'pptp'
                        - 'rtsp'
                        - 'dns-udp'
                        - 'dns-tcp'
                        - 'pmap'
                        - 'rsh'
                        - 'dcerpc'
                        - 'mgcp'
                        - 'gtp-c'
                        - 'gtp-u'
                        - 'gtp-b'
                icmpcode:
                    type: int
                    description: 'ICMP code.'
                icmptype:
                    type: int
                    description: 'ICMP type.'
                iprange:
                    type: str
                    description: 'Start and end of the IP range associated with service.'
                name:
                    type: str
                    description: 'Custom service name.'
                protocol:
                    type: str
                    description: 'Protocol type based on IANA numbers.'
                    choices:
                        - 'ICMP'
                        - 'IP'
                        - 'TCP/UDP/SCTP'
                        - 'ICMP6'
                        - 'HTTP'
                        - 'FTP'
                        - 'CONNECT'
                        - 'SOCKS'
                        - 'ALL'
                        - 'SOCKS-TCP'
                        - 'SOCKS-UDP'
                protocol-number:
                    type: int
                    description: 'IP protocol number.'
                proxy:
                    type: str
                    description: 'Enable/disable web proxy service.'
                    choices:
                        - 'disable'
                        - 'enable'
                sctp-portrange:
                    type: str
                    description: 'Multiple SCTP port ranges.'
                session-ttl:
                    type: int
                    description: 'Session TTL (300 - 604800, 0 = default).'
                tcp-halfclose-timer:
                    type: int
                    description: 'Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec, 0 = default).'
                tcp-halfopen-timer:
                    type: int
                    description: 'Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec, 0 = default).'
                tcp-portrange:
                    type: str
                    description: 'Multiple TCP port ranges.'
                tcp-timewait-timer:
                    type: int
                    description: 'Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec, 0 = default).'
                udp-idle-timer:
                    type: int
                    description: 'UDP half close timeout (0 - 86400 sec, 0 = default).'
                udp-portrange:
                    type: str
                    description: 'Multiple UDP port ranges.'
                visibility:
                    type: str
                    description: 'Enable/disable the visibility of the service on the GUI.'
                    choices:
                        - 'disable'
                        - 'enable'
    schema_object1:
        methods: [delete]
        description: 'Configure custom services.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'Configure custom services.'
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
    schema_object3:
        methods: [move]
        description: 'Configure custom services.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                choices:
                    - 'before'
                    - 'after'
            target:
                type: str
                description: 'Key to the target entry.'

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

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/SERVICE/CUSTOM/{CUSTOM}
      fmgr_firewall_service_custom_obj:
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            custom: <value of string>
         params:
            -
               data:
                  app-category:
                    - <value of integer>
                  app-service-type: <value in [disable, app-id, app-category]>
                  application:
                    - <value of integer>
                  category: <value of string>
                  check-reset-range: <value in [disable, default, strict]>
                  color: <value of integer>
                  comment: <value of string>
                  fqdn: <value of string>
                  helper: <value in [disable, auto, ftp, ...]>
                  icmpcode: <value of integer>
                  icmptype: <value of integer>
                  iprange: <value of string>
                  name: <value of string>
                  protocol: <value in [ICMP, IP, TCP/UDP/SCTP, ...]>
                  protocol-number: <value of integer>
                  proxy: <value in [disable, enable]>
                  sctp-portrange: <value of string>
                  session-ttl: <value of integer>
                  tcp-halfclose-timer: <value of integer>
                  tcp-halfopen-timer: <value of integer>
                  tcp-portrange: <value of string>
                  tcp-timewait-timer: <value of integer>
                  udp-idle-timer: <value of integer>
                  udp-portrange: <value of string>
                  visibility: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/SERVICE/CUSTOM/{CUSTOM}
      fmgr_firewall_service_custom_obj:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            custom: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/SERVICE/CUSTOM/{CUSTOM}
      fmgr_firewall_service_custom_obj:
         method: <value in [move]>
         url_params:
            adom: <value in [none, global, custom dom]>
            custom: <value of string>
         params:
            -
               option: <value in [before, after]>
               target: <value of string>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, delete, move, set, update]
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
            example: '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            app-category:
               type: array
               suboptions:
                  type: int
            app-service-type:
               type: str
               description: 'Application service type.'
            application:
               type: array
               suboptions:
                  type: int
            category:
               type: str
               description: 'Service category.'
            check-reset-range:
               type: str
               description: 'Configure the type of ICMP error message verification.'
            color:
               type: int
               description: 'Color of icon on the GUI.'
            comment:
               type: str
            fqdn:
               type: str
               description: 'Fully qualified domain name.'
            helper:
               type: str
               description: 'Helper name.'
            icmpcode:
               type: int
               description: 'ICMP code.'
            icmptype:
               type: int
               description: 'ICMP type.'
            iprange:
               type: str
               description: 'Start and end of the IP range associated with service.'
            name:
               type: str
               description: 'Custom service name.'
            protocol:
               type: str
               description: 'Protocol type based on IANA numbers.'
            protocol-number:
               type: int
               description: 'IP protocol number.'
            proxy:
               type: str
               description: 'Enable/disable web proxy service.'
            sctp-portrange:
               type: str
               description: 'Multiple SCTP port ranges.'
            session-ttl:
               type: int
               description: 'Session TTL (300 - 604800, 0 = default).'
            tcp-halfclose-timer:
               type: int
               description: 'Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec, 0 = default).'
            tcp-halfopen-timer:
               type: int
               description: 'Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec, 0 = default).'
            tcp-portrange:
               type: str
               description: 'Multiple TCP port ranges.'
            tcp-timewait-timer:
               type: int
               description: 'Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec, 0 = default).'
            udp-idle-timer:
               type: int
               description: 'UDP half close timeout (0 - 86400 sec, 0 = default).'
            udp-portrange:
               type: str
               description: 'Multiple UDP port ranges.'
            visibility:
               type: str
               description: 'Enable/disable the visibility of the service on the GUI.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}'

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
        '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
        '/pm/config/global/obj/firewall/service/custom/{custom}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'custom',
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
                        'app-category': {
                            'type': 'array',
                            'items': {
                                'type': 'integer'
                            }
                        },
                        'app-service-type': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'app-id',
                                'app-category'
                            ]
                        },
                        'application': {
                            'type': 'array',
                            'items': {
                                'type': 'integer'
                            }
                        },
                        'category': {
                            'type': 'string'
                        },
                        'check-reset-range': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'default',
                                'strict'
                            ]
                        },
                        'color': {
                            'type': 'integer'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'fqdn': {
                            'type': 'string'
                        },
                        'helper': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'auto',
                                'ftp',
                                'tftp',
                                'ras',
                                'h323',
                                'tns',
                                'mms',
                                'sip',
                                'pptp',
                                'rtsp',
                                'dns-udp',
                                'dns-tcp',
                                'pmap',
                                'rsh',
                                'dcerpc',
                                'mgcp',
                                'gtp-c',
                                'gtp-u',
                                'gtp-b'
                            ]
                        },
                        'icmpcode': {
                            'type': 'integer'
                        },
                        'icmptype': {
                            'type': 'integer'
                        },
                        'iprange': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'protocol': {
                            'type': 'string',
                            'enum': [
                                'ICMP',
                                'IP',
                                'TCP/UDP/SCTP',
                                'ICMP6',
                                'HTTP',
                                'FTP',
                                'CONNECT',
                                'SOCKS',
                                'ALL',
                                'SOCKS-TCP',
                                'SOCKS-UDP'
                            ]
                        },
                        'protocol-number': {
                            'type': 'integer'
                        },
                        'proxy': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'sctp-portrange': {
                            'type': 'string'
                        },
                        'session-ttl': {
                            'type': 'integer'
                        },
                        'tcp-halfclose-timer': {
                            'type': 'integer'
                        },
                        'tcp-halfopen-timer': {
                            'type': 'integer'
                        },
                        'tcp-portrange': {
                            'type': 'string'
                        },
                        'tcp-timewait-timer': {
                            'type': 'integer'
                        },
                        'udp-idle-timer': {
                            'type': 'integer'
                        },
                        'udp-portrange': {
                            'type': 'string'
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
            ],
            'object3': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'before',
                            'after'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'target',
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
            'move': 'object3',
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
                'clone',
                'delete',
                'get',
                'move',
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
