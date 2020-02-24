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
module: fmgr_ips_sensor
short_description: Configure IPS sensor.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/ips/sensor
    - /pm/config/global/obj/ips/sensor
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
        description: 'Configure IPS sensor.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    block-malicious-url:
                        type: str
                        description: 'Enable/disable malicious URL blocking.'
                        choices:
                            - 'disable'
                            - 'enable'
                    comment:
                        type: str
                        description: 'Comment.'
                    entries:
                        -
                            action:
                                type: str
                                description: 'Action taken with traffic in which signatures are detected.'
                                choices:
                                    - 'pass'
                                    - 'block'
                                    - 'reset'
                                    - 'default'
                            application:
                                -
                                    type: str
                            exempt-ip:
                                -
                                    dst-ip:
                                        type: str
                                        description: 'Destination IP address and netmask.'
                                    id:
                                        type: int
                                        description: 'Exempt IP ID.'
                                    src-ip:
                                        type: str
                                        description: 'Source IP address and netmask.'
                            id:
                                type: int
                                description: 'Rule ID in IPS database (0 - 4294967295).'
                            location:
                                -
                                    type: str
                            log:
                                type: str
                                description: 'Enable/disable logging of signatures included in filter.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            log-attack-context:
                                type: str
                                description: 'Enable/disable logging of attack context: URL buffer, header buffer, body buffer, packet buffer.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            log-packet:
                                type: str
                                description: 'Enable/disable packet logging. Enable to save the packet that triggers the filter. You can download the packet...'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            os:
                                -
                                    type: str
                            protocol:
                                -
                                    type: str
                            quarantine:
                                type: str
                                description: 'Quarantine method.'
                                choices:
                                    - 'none'
                                    - 'attacker'
                                    - 'both'
                                    - 'interface'
                            quarantine-expiry:
                                type: str
                                description: 'Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m, default = 5m). Requires quarantine...'
                            quarantine-log:
                                type: str
                                description: 'Enable/disable quarantine logging.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            rate-count:
                                type: int
                                description: 'Count of the rate.'
                            rate-duration:
                                type: int
                                description: 'Duration (sec) of the rate.'
                            rate-mode:
                                type: str
                                description: 'Rate limit mode.'
                                choices:
                                    - 'periodical'
                                    - 'continuous'
                            rate-track:
                                type: str
                                description: 'Track the packet protocol field.'
                                choices:
                                    - 'none'
                                    - 'src-ip'
                                    - 'dest-ip'
                                    - 'dhcp-client-mac'
                                    - 'dns-domain'
                            rule:
                                type: str
                                description: 'Identifies the predefined or custom IPS signatures to add to the sensor.'
                            severity:
                                -
                                    type: str
                            status:
                                type: str
                                description: 'Status of the signatures included in filter. default enables the filter and only use filters with default stat...'
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'default'
                    extended-log:
                        type: str
                        description: 'Enable/disable extended logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    filter:
                        -
                            action:
                                type: str
                                description: 'Action of selected rules.'
                                choices:
                                    - 'pass'
                                    - 'block'
                                    - 'default'
                                    - 'reset'
                            application:
                                -
                                    type: str
                            location:
                                -
                                    type: str
                            log:
                                type: str
                                description: 'Enable/disable logging of selected rules.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'default'
                            log-packet:
                                type: str
                                description: 'Enable/disable packet logging of selected rules.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'default'
                            name:
                                type: str
                                description: 'Filter name.'
                            os:
                                -
                                    type: str
                            protocol:
                                -
                                    type: str
                            quarantine:
                                type: str
                                description: 'Quarantine IP or interface.'
                                choices:
                                    - 'none'
                                    - 'attacker'
                                    - 'both'
                                    - 'interface'
                            quarantine-expiry:
                                type: int
                                description: 'Duration of quarantine in minute.'
                            quarantine-log:
                                type: str
                                description: 'Enable/disable logging of selected quarantine.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                -
                                    type: str
                            status:
                                type: str
                                description: 'Selected rules status.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'default'
                    name:
                        type: str
                        description: 'Sensor name.'
                    override:
                        -
                            action:
                                type: str
                                description: 'Action of override rule.'
                                choices:
                                    - 'pass'
                                    - 'block'
                                    - 'reset'
                            exempt-ip:
                                -
                                    dst-ip:
                                        type: str
                                        description: 'Destination IP address and netmask.'
                                    id:
                                        type: int
                                        description: 'Exempt IP ID.'
                                    src-ip:
                                        type: str
                                        description: 'Source IP address and netmask.'
                            log:
                                type: str
                                description: 'Enable/disable logging.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            log-packet:
                                type: str
                                description: 'Enable/disable packet logging.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            quarantine:
                                type: str
                                description: 'Quarantine IP or interface.'
                                choices:
                                    - 'none'
                                    - 'attacker'
                                    - 'both'
                                    - 'interface'
                            quarantine-expiry:
                                type: int
                                description: 'Duration of quarantine in minute.'
                            quarantine-log:
                                type: str
                                description: 'Enable/disable logging of selected quarantine.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            rule-id:
                                type: int
                                description: 'Override rule ID.'
                            status:
                                type: str
                                description: 'Enable/disable status of override rule.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                    replacemsg-group:
                        type: str
                        description: 'Replacement message group.'
    schema_object1:
        methods: [get]
        description: 'Configure IPS sensor.'
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
                            - 'block-malicious-url'
                            - 'comment'
                            - 'extended-log'
                            - 'name'
                            - 'replacemsg-group'
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
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/OBJ/IPS/SENSOR
      fmgr_ips_sensor:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     block-malicious-url: <value in [disable, enable]>
                     comment: <value of string>
                     entries:
                       -
                           action: <value in [pass, block, reset, ...]>
                           application:
                             - <value of string>
                           exempt-ip:
                             -
                                 dst-ip: <value of string>
                                 id: <value of integer>
                                 src-ip: <value of string>
                           id: <value of integer>
                           location:
                             - <value of string>
                           log: <value in [disable, enable]>
                           log-attack-context: <value in [disable, enable]>
                           log-packet: <value in [disable, enable]>
                           os:
                             - <value of string>
                           protocol:
                             - <value of string>
                           quarantine: <value in [none, attacker, both, ...]>
                           quarantine-expiry: <value of string>
                           quarantine-log: <value in [disable, enable]>
                           rate-count: <value of integer>
                           rate-duration: <value of integer>
                           rate-mode: <value in [periodical, continuous]>
                           rate-track: <value in [none, src-ip, dest-ip, ...]>
                           rule: <value of string>
                           severity:
                             - <value of string>
                           status: <value in [disable, enable, default]>
                     extended-log: <value in [disable, enable]>
                     filter:
                       -
                           action: <value in [pass, block, default, ...]>
                           application:
                             - <value of string>
                           location:
                             - <value of string>
                           log: <value in [disable, enable, default]>
                           log-packet: <value in [disable, enable, default]>
                           name: <value of string>
                           os:
                             - <value of string>
                           protocol:
                             - <value of string>
                           quarantine: <value in [none, attacker, both, ...]>
                           quarantine-expiry: <value of integer>
                           quarantine-log: <value in [disable, enable]>
                           severity:
                             - <value of string>
                           status: <value in [disable, enable, default]>
                     name: <value of string>
                     override:
                       -
                           action: <value in [pass, block, reset]>
                           exempt-ip:
                             -
                                 dst-ip: <value of string>
                                 id: <value of integer>
                                 src-ip: <value of string>
                           log: <value in [disable, enable]>
                           log-packet: <value in [disable, enable]>
                           quarantine: <value in [none, attacker, both, ...]>
                           quarantine-expiry: <value of integer>
                           quarantine-log: <value in [disable, enable]>
                           rule-id: <value of integer>
                           status: <value in [disable, enable]>
                     replacemsg-group: <value of string>

    - name: REQUESTING /PM/CONFIG/OBJ/IPS/SENSOR
      fmgr_ips_sensor:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [block-malicious-url, comment, extended-log, ...]>
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
            example: '/pm/config/adom/{adom}/obj/ips/sensor'
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
               block-malicious-url:
                  type: str
                  description: 'Enable/disable malicious URL blocking.'
               comment:
                  type: str
                  description: 'Comment.'
               entries:
                  type: array
                  suboptions:
                     action:
                        type: str
                        description: 'Action taken with traffic in which signatures are detected.'
                     application:
                        type: array
                        suboptions:
                           type: str
                     exempt-ip:
                        type: array
                        suboptions:
                           dst-ip:
                              type: str
                              description: 'Destination IP address and netmask.'
                           id:
                              type: int
                              description: 'Exempt IP ID.'
                           src-ip:
                              type: str
                              description: 'Source IP address and netmask.'
                     id:
                        type: int
                        description: 'Rule ID in IPS database (0 - 4294967295).'
                     location:
                        type: array
                        suboptions:
                           type: str
                     log:
                        type: str
                        description: 'Enable/disable logging of signatures included in filter.'
                     log-attack-context:
                        type: str
                        description: 'Enable/disable logging of attack context: URL buffer, header buffer, body buffer, packet buffer.'
                     log-packet:
                        type: str
                        description: 'Enable/disable packet logging. Enable to save the packet that triggers the filter. You can download the packets in pca...'
                     os:
                        type: array
                        suboptions:
                           type: str
                     protocol:
                        type: array
                        suboptions:
                           type: str
                     quarantine:
                        type: str
                        description: 'Quarantine method.'
                     quarantine-expiry:
                        type: str
                        description: 'Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m, default = 5m). Requires quarantine set to ...'
                     quarantine-log:
                        type: str
                        description: 'Enable/disable quarantine logging.'
                     rate-count:
                        type: int
                        description: 'Count of the rate.'
                     rate-duration:
                        type: int
                        description: 'Duration (sec) of the rate.'
                     rate-mode:
                        type: str
                        description: 'Rate limit mode.'
                     rate-track:
                        type: str
                        description: 'Track the packet protocol field.'
                     rule:
                        type: str
                        description: 'Identifies the predefined or custom IPS signatures to add to the sensor.'
                     severity:
                        type: array
                        suboptions:
                           type: str
                     status:
                        type: str
                        description: 'Status of the signatures included in filter. default enables the filter and only use filters with default status of en...'
               extended-log:
                  type: str
                  description: 'Enable/disable extended logging.'
               filter:
                  type: array
                  suboptions:
                     action:
                        type: str
                        description: 'Action of selected rules.'
                     application:
                        type: array
                        suboptions:
                           type: str
                     location:
                        type: array
                        suboptions:
                           type: str
                     log:
                        type: str
                        description: 'Enable/disable logging of selected rules.'
                     log-packet:
                        type: str
                        description: 'Enable/disable packet logging of selected rules.'
                     name:
                        type: str
                        description: 'Filter name.'
                     os:
                        type: array
                        suboptions:
                           type: str
                     protocol:
                        type: array
                        suboptions:
                           type: str
                     quarantine:
                        type: str
                        description: 'Quarantine IP or interface.'
                     quarantine-expiry:
                        type: int
                        description: 'Duration of quarantine in minute.'
                     quarantine-log:
                        type: str
                        description: 'Enable/disable logging of selected quarantine.'
                     severity:
                        type: array
                        suboptions:
                           type: str
                     status:
                        type: str
                        description: 'Selected rules status.'
               name:
                  type: str
                  description: 'Sensor name.'
               override:
                  type: array
                  suboptions:
                     action:
                        type: str
                        description: 'Action of override rule.'
                     exempt-ip:
                        type: array
                        suboptions:
                           dst-ip:
                              type: str
                              description: 'Destination IP address and netmask.'
                           id:
                              type: int
                              description: 'Exempt IP ID.'
                           src-ip:
                              type: str
                              description: 'Source IP address and netmask.'
                     log:
                        type: str
                        description: 'Enable/disable logging.'
                     log-packet:
                        type: str
                        description: 'Enable/disable packet logging.'
                     quarantine:
                        type: str
                        description: 'Quarantine IP or interface.'
                     quarantine-expiry:
                        type: int
                        description: 'Duration of quarantine in minute.'
                     quarantine-log:
                        type: str
                        description: 'Enable/disable logging of selected quarantine.'
                     rule-id:
                        type: int
                        description: 'Override rule ID.'
                     status:
                        type: str
                        description: 'Enable/disable status of override rule.'
               replacemsg-group:
                  type: str
                  description: 'Replacement message group.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/ips/sensor'

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
        '/pm/config/adom/{adom}/obj/ips/sensor',
        '/pm/config/global/obj/ips/sensor'
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
                        'block-malicious-url': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'entries': {
                            'type': 'array',
                            'items': {
                                'action': {
                                    'type': 'string',
                                    'enum': [
                                        'pass',
                                        'block',
                                        'reset',
                                        'default'
                                    ]
                                },
                                'application': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'exempt-ip': {
                                    'type': 'array',
                                    'items': {
                                        'dst-ip': {
                                            'type': 'string'
                                        },
                                        'id': {
                                            'type': 'integer'
                                        },
                                        'src-ip': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'location': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'log-attack-context': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'log-packet': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'os': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'protocol': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'quarantine': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'attacker',
                                        'both',
                                        'interface'
                                    ]
                                },
                                'quarantine-expiry': {
                                    'type': 'string'
                                },
                                'quarantine-log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'rate-count': {
                                    'type': 'integer'
                                },
                                'rate-duration': {
                                    'type': 'integer'
                                },
                                'rate-mode': {
                                    'type': 'string',
                                    'enum': [
                                        'periodical',
                                        'continuous'
                                    ]
                                },
                                'rate-track': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'src-ip',
                                        'dest-ip',
                                        'dhcp-client-mac',
                                        'dns-domain'
                                    ]
                                },
                                'rule': {
                                    'type': 'string'
                                },
                                'severity': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'status': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'default'
                                    ]
                                }
                            }
                        },
                        'extended-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'filter': {
                            'type': 'array',
                            'items': {
                                'action': {
                                    'type': 'string',
                                    'enum': [
                                        'pass',
                                        'block',
                                        'default',
                                        'reset'
                                    ]
                                },
                                'application': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'location': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'default'
                                    ]
                                },
                                'log-packet': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'default'
                                    ]
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'os': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'protocol': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'quarantine': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'attacker',
                                        'both',
                                        'interface'
                                    ]
                                },
                                'quarantine-expiry': {
                                    'type': 'integer'
                                },
                                'quarantine-log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'severity': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'status': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'default'
                                    ]
                                }
                            }
                        },
                        'name': {
                            'type': 'string'
                        },
                        'override': {
                            'type': 'array',
                            'items': {
                                'action': {
                                    'type': 'string',
                                    'enum': [
                                        'pass',
                                        'block',
                                        'reset'
                                    ]
                                },
                                'exempt-ip': {
                                    'type': 'array',
                                    'items': {
                                        'dst-ip': {
                                            'type': 'string'
                                        },
                                        'id': {
                                            'type': 'integer'
                                        },
                                        'src-ip': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'log-packet': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'quarantine': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'attacker',
                                        'both',
                                        'interface'
                                    ]
                                },
                                'quarantine-expiry': {
                                    'type': 'integer'
                                },
                                'quarantine-log': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'rule-id': {
                                    'type': 'integer'
                                },
                                'status': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                }
                            }
                        },
                        'replacemsg-group': {
                            'type': 'string'
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
                                'block-malicious-url',
                                'comment',
                                'extended-log',
                                'name',
                                'replacemsg-group'
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
