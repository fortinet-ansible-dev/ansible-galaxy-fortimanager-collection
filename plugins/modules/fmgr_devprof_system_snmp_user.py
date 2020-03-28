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
module: fmgr_devprof_system_snmp_user
short_description: SNMP user configuration.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user
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
        methods: [add, set, update]
        description: 'SNMP user configuration.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    auth-proto:
                        type: str
                        description: 'Authentication protocol.'
                        choices:
                            - 'md5'
                            - 'sha'
                    auth-pwd:
                        -
                            type: str
                    events:
                        -
                            type: str
                            choices:
                                - 'cpu-high'
                                - 'mem-low'
                                - 'log-full'
                                - 'intf-ip'
                                - 'vpn-tun-up'
                                - 'vpn-tun-down'
                                - 'ha-switch'
                                - 'fm-conf-change'
                                - 'ips-signature'
                                - 'ips-anomaly'
                                - 'temperature-high'
                                - 'voltage-alert'
                                - 'av-virus'
                                - 'av-oversize'
                                - 'av-pattern'
                                - 'av-fragmented'
                                - 'ha-hb-failure'
                                - 'fan-failure'
                                - 'ha-member-up'
                                - 'ha-member-down'
                                - 'ent-conf-change'
                                - 'av-conserve'
                                - 'av-bypass'
                                - 'av-oversize-passed'
                                - 'av-oversize-blocked'
                                - 'ips-pkg-update'
                                - 'fm-if-change'
                                - 'power-supply-failure'
                                - 'amc-bypass'
                                - 'faz-disconnect'
                                - 'bgp-established'
                                - 'bgp-backward-transition'
                                - 'wc-ap-up'
                                - 'wc-ap-down'
                                - 'fswctl-session-up'
                                - 'fswctl-session-down'
                                - 'ips-fail-open'
                                - 'load-balance-real-server-down'
                                - 'device-new'
                                - 'enter-intf-bypass'
                                - 'exit-intf-bypass'
                                - 'per-cpu-high'
                                - 'power-blade-down'
                                - 'confsync_failure'
                    ha-direct:
                        type: str
                        description: 'Enable/disable direct management of HA cluster members.'
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: 'SNMP user name.'
                    notify-hosts:
                        -
                            type: str
                    notify-hosts6:
                        type: str
                        description: 'IPv6 SNMP managers to send notifications (traps) to.'
                    priv-proto:
                        type: str
                        description: 'Privacy (encryption) protocol.'
                        choices:
                            - 'aes'
                            - 'des'
                            - 'aes256'
                            - 'aes256cisco'
                    priv-pwd:
                        -
                            type: str
                    queries:
                        type: str
                        description: 'Enable/disable SNMP queries for this user.'
                        choices:
                            - 'disable'
                            - 'enable'
                    query-port:
                        type: int
                        description: 'SNMPv3 query port (default = 161).'
                    security-level:
                        type: str
                        description: 'Security level for message authentication and encryption.'
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
                    source-ip:
                        type: str
                        description: 'Source IP for SNMP trap.'
                    source-ipv6:
                        type: str
                        description: 'Source IPv6 for SNMP trap.'
                    status:
                        type: str
                        description: 'Enable/disable this SNMP user.'
                        choices:
                            - 'disable'
                            - 'enable'
                    trap-lport:
                        type: int
                        description: 'SNMPv3 local trap port (default = 162).'
                    trap-rport:
                        type: int
                        description: 'SNMPv3 trap remote port (default = 162).'
                    trap-status:
                        type: str
                        description: 'Enable/disable traps for this SNMP user.'
                        choices:
                            - 'disable'
                            - 'enable'
    schema_object1:
        methods: [get]
        description: 'SNMP user configuration.'
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
                            - 'auth-proto'
                            - 'auth-pwd'
                            - 'events'
                            - 'ha-direct'
                            - 'name'
                            - 'notify-hosts'
                            - 'notify-hosts6'
                            - 'priv-proto'
                            - 'priv-pwd'
                            - 'queries'
                            - 'query-port'
                            - 'security-level'
                            - 'source-ip'
                            - 'source-ipv6'
                            - 'status'
                            - 'trap-lport'
                            - 'trap-rport'
                            - 'trap-status'
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

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/SNMP/USER
      fmgr_devprof_system_snmp_user:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               data:
                 -
                     auth-proto: <value in [md5, sha]>
                     auth-pwd:
                       - <value of string>
                     events:
                       - <value in [cpu-high, mem-low, log-full, ...]>
                     ha-direct: <value in [disable, enable]>
                     name: <value of string>
                     notify-hosts:
                       - <value of string>
                     notify-hosts6: <value of string>
                     priv-proto: <value in [aes, des, aes256, ...]>
                     priv-pwd:
                       - <value of string>
                     queries: <value in [disable, enable]>
                     query-port: <value of integer>
                     security-level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
                     source-ip: <value of string>
                     source-ipv6: <value of string>
                     status: <value in [disable, enable]>
                     trap-lport: <value of integer>
                     trap-rport: <value of integer>
                     trap-status: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/SNMP/USER
      fmgr_devprof_system_snmp_user:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [auth-proto, auth-pwd, events, ...]>
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
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'
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
               auth-proto:
                  type: str
                  description: 'Authentication protocol.'
               auth-pwd:
                  type: array
                  suboptions:
                     type: str
               events:
                  type: array
                  suboptions:
                     type: str
               ha-direct:
                  type: str
                  description: 'Enable/disable direct management of HA cluster members.'
               name:
                  type: str
                  description: 'SNMP user name.'
               notify-hosts:
                  type: array
                  suboptions:
                     type: str
               notify-hosts6:
                  type: str
                  description: 'IPv6 SNMP managers to send notifications (traps) to.'
               priv-proto:
                  type: str
                  description: 'Privacy (encryption) protocol.'
               priv-pwd:
                  type: array
                  suboptions:
                     type: str
               queries:
                  type: str
                  description: 'Enable/disable SNMP queries for this user.'
               query-port:
                  type: int
                  description: 'SNMPv3 query port (default = 161).'
               security-level:
                  type: str
                  description: 'Security level for message authentication and encryption.'
               source-ip:
                  type: str
                  description: 'Source IP for SNMP trap.'
               source-ipv6:
                  type: str
                  description: 'Source IPv6 for SNMP trap.'
               status:
                  type: str
                  description: 'Enable/disable this SNMP user.'
               trap-lport:
                  type: int
                  description: 'SNMPv3 local trap port (default = 162).'
               trap-rport:
                  type: int
                  description: 'SNMPv3 trap remote port (default = 162).'
               trap-status:
                  type: str
                  description: 'Enable/disable traps for this SNMP user.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'
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
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'auth-proto': {
                            'type': 'string',
                            'enum': [
                                'md5',
                                'sha'
                            ]
                        },
                        'auth-pwd': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'events': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'cpu-high',
                                    'mem-low',
                                    'log-full',
                                    'intf-ip',
                                    'vpn-tun-up',
                                    'vpn-tun-down',
                                    'ha-switch',
                                    'fm-conf-change',
                                    'ips-signature',
                                    'ips-anomaly',
                                    'temperature-high',
                                    'voltage-alert',
                                    'av-virus',
                                    'av-oversize',
                                    'av-pattern',
                                    'av-fragmented',
                                    'ha-hb-failure',
                                    'fan-failure',
                                    'ha-member-up',
                                    'ha-member-down',
                                    'ent-conf-change',
                                    'av-conserve',
                                    'av-bypass',
                                    'av-oversize-passed',
                                    'av-oversize-blocked',
                                    'ips-pkg-update',
                                    'fm-if-change',
                                    'power-supply-failure',
                                    'amc-bypass',
                                    'faz-disconnect',
                                    'bgp-established',
                                    'bgp-backward-transition',
                                    'wc-ap-up',
                                    'wc-ap-down',
                                    'fswctl-session-up',
                                    'fswctl-session-down',
                                    'ips-fail-open',
                                    'load-balance-real-server-down',
                                    'device-new',
                                    'enter-intf-bypass',
                                    'exit-intf-bypass',
                                    'per-cpu-high',
                                    'power-blade-down',
                                    'confsync_failure'
                                ]
                            }
                        },
                        'ha-direct': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        },
                        'notify-hosts': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'notify-hosts6': {
                            'type': 'string'
                        },
                        'priv-proto': {
                            'type': 'string',
                            'enum': [
                                'aes',
                                'des',
                                'aes256',
                                'aes256cisco'
                            ]
                        },
                        'priv-pwd': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'queries': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'query-port': {
                            'type': 'integer'
                        },
                        'security-level': {
                            'type': 'string',
                            'enum': [
                                'no-auth-no-priv',
                                'auth-no-priv',
                                'auth-priv'
                            ]
                        },
                        'source-ip': {
                            'type': 'string'
                        },
                        'source-ipv6': {
                            'type': 'string'
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'trap-lport': {
                            'type': 'integer'
                        },
                        'trap-rport': {
                            'type': 'integer'
                        },
                        'trap-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
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
                                'auth-proto',
                                'auth-pwd',
                                'events',
                                'ha-direct',
                                'name',
                                'notify-hosts',
                                'notify-hosts6',
                                'priv-proto',
                                'priv-pwd',
                                'queries',
                                'query-port',
                                'security-level',
                                'source-ip',
                                'source-ipv6',
                                'status',
                                'trap-lport',
                                'trap-rport',
                                'trap-status'
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
