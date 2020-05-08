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
module: fmgr_devprof_system_snmp_community_obj
short_description: SNMP community configuration.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get set update ] the following apis.
    - /pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}
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
            community:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'SNMP community configuration.'
        api_categories: [api_tag0]
        api_tag0:
            data:
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
                            - 'ha-hb-failure'
                            - 'ips-signature'
                            - 'ips-anomaly'
                            - 'av-virus'
                            - 'av-oversize'
                            - 'av-pattern'
                            - 'av-fragmented'
                            - 'fm-if-change'
                            - 'fm-conf-change'
                            - 'temperature-high'
                            - 'voltage-alert'
                            - 'ha-member-up'
                            - 'ha-member-down'
                            - 'ent-conf-change'
                            - 'av-conserve'
                            - 'av-bypass'
                            - 'av-oversize-passed'
                            - 'av-oversize-blocked'
                            - 'ips-pkg-update'
                            - 'power-supply-failure'
                            - 'amc-bypass'
                            - 'faz-disconnect'
                            - 'fan-failure'
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
                hosts:
                    -
                        ha-direct:
                            type: str
                            description: 'Enable/disable direct management of HA cluster members.'
                            choices:
                                - 'disable'
                                - 'enable'
                        host-type:
                            type: str
                            description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                            choices:
                                - 'any'
                                - 'query'
                                - 'trap'
                        id:
                            type: int
                            description: 'Host entry ID.'
                        ip:
                            type: str
                            description: 'IPv4 address of the SNMP manager (host).'
                        source-ip:
                            type: str
                            description: 'Source IPv4 address for SNMP traps.'
                hosts6:
                    -
                        ha-direct:
                            type: str
                            description: 'Enable/disable direct management of HA cluster members.'
                            choices:
                                - 'disable'
                                - 'enable'
                        host-type:
                            type: str
                            description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                            choices:
                                - 'any'
                                - 'query'
                                - 'trap'
                        id:
                            type: int
                            description: 'Host6 entry ID.'
                        ipv6:
                            type: str
                            description: 'SNMP manager IPv6 address prefix.'
                        source-ipv6:
                            type: str
                            description: 'Source IPv6 address for SNMP traps.'
                id:
                    type: int
                    description: 'Community ID.'
                name:
                    type: str
                    description: 'Community name.'
                query-v1-port:
                    type: int
                    description: 'SNMP v1 query port (default = 161).'
                query-v1-status:
                    type: str
                    description: 'Enable/disable SNMP v1 queries.'
                    choices:
                        - 'disable'
                        - 'enable'
                query-v2c-port:
                    type: int
                    description: 'SNMP v2c query port (default = 161).'
                query-v2c-status:
                    type: str
                    description: 'Enable/disable SNMP v2c queries.'
                    choices:
                        - 'disable'
                        - 'enable'
                status:
                    type: str
                    description: 'Enable/disable this SNMP community.'
                    choices:
                        - 'disable'
                        - 'enable'
                trap-v1-lport:
                    type: int
                    description: 'SNMP v1 trap local port (default = 162).'
                trap-v1-rport:
                    type: int
                    description: 'SNMP v1 trap remote port (default = 162).'
                trap-v1-status:
                    type: str
                    description: 'Enable/disable SNMP v1 traps.'
                    choices:
                        - 'disable'
                        - 'enable'
                trap-v2c-lport:
                    type: int
                    description: 'SNMP v2c trap local port (default = 162).'
                trap-v2c-rport:
                    type: int
                    description: 'SNMP v2c trap remote port (default = 162).'
                trap-v2c-status:
                    type: str
                    description: 'Enable/disable SNMP v2c traps.'
                    choices:
                        - 'disable'
                        - 'enable'
    schema_object1:
        methods: [delete]
        description: 'SNMP community configuration.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'SNMP community configuration.'
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
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/SNMP/COMMUNITY/{COMMUNITY}
      fmgr_devprof_system_snmp_community_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
            community: <value of string>
         params:
            -
               data:
                  events:
                    - <value in [cpu-high, mem-low, log-full, ...]>
                  hosts:
                    -
                        ha-direct: <value in [disable, enable]>
                        host-type: <value in [any, query, trap]>
                        id: <value of integer>
                        ip: <value of string>
                        source-ip: <value of string>
                  hosts6:
                    -
                        ha-direct: <value in [disable, enable]>
                        host-type: <value in [any, query, trap]>
                        id: <value of integer>
                        ipv6: <value of string>
                        source-ipv6: <value of string>
                  id: <value of integer>
                  name: <value of string>
                  query-v1-port: <value of integer>
                  query-v1-status: <value in [disable, enable]>
                  query-v2c-port: <value of integer>
                  query-v2c-status: <value in [disable, enable]>
                  status: <value in [disable, enable]>
                  trap-v1-lport: <value of integer>
                  trap-v1-rport: <value of integer>
                  trap-v1-status: <value in [disable, enable]>
                  trap-v2c-lport: <value of integer>
                  trap-v2c-rport: <value of integer>
                  trap-v2c-status: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/DEVPROF/{DEVPROF}/SYSTEM/SNMP/COMMUNITY/{COMMUNITY}
      fmgr_devprof_system_snmp_community_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            devprof: <value of string>
            community: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, set, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            id:
               type: int
               description: 'Community ID.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
return_of_api_category_0:
   description: items returned for method:[delete]
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
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            events:
               type: array
               suboptions:
                  type: str
            hosts:
               type: array
               suboptions:
                  ha-direct:
                     type: str
                     description: 'Enable/disable direct management of HA cluster members.'
                  host-type:
                     type: str
                     description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                  id:
                     type: int
                     description: 'Host entry ID.'
                  ip:
                     type: str
                     description: 'IPv4 address of the SNMP manager (host).'
                  source-ip:
                     type: str
                     description: 'Source IPv4 address for SNMP traps.'
            hosts6:
               type: array
               suboptions:
                  ha-direct:
                     type: str
                     description: 'Enable/disable direct management of HA cluster members.'
                  host-type:
                     type: str
                     description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                  id:
                     type: int
                     description: 'Host6 entry ID.'
                  ipv6:
                     type: str
                     description: 'SNMP manager IPv6 address prefix.'
                  source-ipv6:
                     type: str
                     description: 'Source IPv6 address for SNMP traps.'
            id:
               type: int
               description: 'Community ID.'
            name:
               type: str
               description: 'Community name.'
            query-v1-port:
               type: int
               description: 'SNMP v1 query port (default = 161).'
            query-v1-status:
               type: str
               description: 'Enable/disable SNMP v1 queries.'
            query-v2c-port:
               type: int
               description: 'SNMP v2c query port (default = 161).'
            query-v2c-status:
               type: str
               description: 'Enable/disable SNMP v2c queries.'
            status:
               type: str
               description: 'Enable/disable this SNMP community.'
            trap-v1-lport:
               type: int
               description: 'SNMP v1 trap local port (default = 162).'
            trap-v1-rport:
               type: int
               description: 'SNMP v1 trap remote port (default = 162).'
            trap-v1-status:
               type: str
               description: 'Enable/disable SNMP v1 traps.'
            trap-v2c-lport:
               type: int
               description: 'SNMP v2c trap local port (default = 162).'
            trap-v2c-rport:
               type: int
               description: 'SNMP v2c trap remote port (default = 162).'
            trap-v2c-status:
               type: str
               description: 'Enable/disable SNMP v2c traps.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'devprof',
            'type': 'string'
        },
        {
            'name': 'community',
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
                                    'ha-hb-failure',
                                    'ips-signature',
                                    'ips-anomaly',
                                    'av-virus',
                                    'av-oversize',
                                    'av-pattern',
                                    'av-fragmented',
                                    'fm-if-change',
                                    'fm-conf-change',
                                    'temperature-high',
                                    'voltage-alert',
                                    'ha-member-up',
                                    'ha-member-down',
                                    'ent-conf-change',
                                    'av-conserve',
                                    'av-bypass',
                                    'av-oversize-passed',
                                    'av-oversize-blocked',
                                    'ips-pkg-update',
                                    'power-supply-failure',
                                    'amc-bypass',
                                    'faz-disconnect',
                                    'fan-failure',
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
                        'hosts': {
                            'type': 'array',
                            'items': {
                                'ha-direct': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'host-type': {
                                    'type': 'string',
                                    'enum': [
                                        'any',
                                        'query',
                                        'trap'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'ip': {
                                    'type': 'string'
                                },
                                'source-ip': {
                                    'type': 'string'
                                }
                            }
                        },
                        'hosts6': {
                            'type': 'array',
                            'items': {
                                'ha-direct': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'host-type': {
                                    'type': 'string',
                                    'enum': [
                                        'any',
                                        'query',
                                        'trap'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'ipv6': {
                                    'type': 'string'
                                },
                                'source-ipv6': {
                                    'type': 'string'
                                }
                            }
                        },
                        'id': {
                            'type': 'integer'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'query-v1-port': {
                            'type': 'integer'
                        },
                        'query-v1-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'query-v2c-port': {
                            'type': 'integer'
                        },
                        'query-v2c-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'trap-v1-lport': {
                            'type': 'integer'
                        },
                        'trap-v1-rport': {
                            'type': 'integer'
                        },
                        'trap-v1-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'trap-v2c-lport': {
                            'type': 'integer'
                        },
                        'trap-v2c-rport': {
                            'type': 'integer'
                        },
                        'trap-v2c-status': {
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
