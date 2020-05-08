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
module: fmgr_application_list
short_description: Configure application control lists.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/application/list
    - /pm/config/global/obj/application/list
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
    schema_object0:
        methods: [add, set, update]
        description: 'Configure application control lists.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    app-replacemsg:
                        type: str
                        description: 'Enable/disable replacement messages for blocked applications.'
                        choices:
                            - 'disable'
                            - 'enable'
                    comment:
                        type: str
                        description: 'comments'
                    deep-app-inspection:
                        type: str
                        description: 'Enable/disable deep application inspection.'
                        choices:
                            - 'disable'
                            - 'enable'
                    entries:
                        -
                            action:
                                type: str
                                description: 'Pass or block traffic, or reset connection for traffic from this application.'
                                choices:
                                    - 'pass'
                                    - 'block'
                                    - 'reset'
                            application:
                                -
                                    type: int
                            behavior:
                                -
                                    type: str
                            category:
                                type: str
                                description: 'Category ID list.'
                            id:
                                type: int
                                description: 'Entry ID.'
                            log:
                                type: str
                                description: 'Enable/disable logging for this application list.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            log-packet:
                                type: str
                                description: 'Enable/disable packet logging.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            parameters:
                                -
                                    id:
                                        type: int
                                        description: 'Parameter ID.'
                                    value:
                                        type: str
                                        description: 'Parameter value.'
                            per-ip-shaper:
                                type: str
                                description: 'Per-IP traffic shaper.'
                            popularity:
                                -
                                    type: str
                                    choices:
                                        - '1'
                                        - '2'
                                        - '3'
                                        - '4'
                                        - '5'
                            protocols:
                                -
                                    type: str
                            quarantine:
                                type: str
                                description: 'Quarantine method.'
                                choices:
                                    - 'none'
                                    - 'attacker'
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
                            risk:
                                -
                                    type: int
                            session-ttl:
                                type: int
                                description: 'Session TTL (0 = default).'
                            shaper:
                                type: str
                                description: 'Traffic shaper.'
                            shaper-reverse:
                                type: str
                                description: 'Reverse traffic shaper.'
                            sub-category:
                                -
                                    type: int
                            technology:
                                -
                                    type: str
                            vendor:
                                -
                                    type: str
                    extended-log:
                        type: str
                        description: 'Enable/disable extended logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: 'List name.'
                    options:
                        -
                            type: str
                            choices:
                                - 'allow-dns'
                                - 'allow-icmp'
                                - 'allow-http'
                                - 'allow-ssl'
                                - 'allow-quic'
                    other-application-action:
                        type: str
                        description: 'Action for other applications.'
                        choices:
                            - 'pass'
                            - 'block'
                    other-application-log:
                        type: str
                        description: 'Enable/disable logging for other applications.'
                        choices:
                            - 'disable'
                            - 'enable'
                    p2p-black-list:
                        -
                            type: str
                            choices:
                                - 'skype'
                                - 'edonkey'
                                - 'bittorrent'
                    replacemsg-group:
                        type: str
                        description: 'Replacement message group.'
                    unknown-application-action:
                        type: str
                        description: 'Pass or block traffic from unknown applications.'
                        choices:
                            - 'pass'
                            - 'block'
                    unknown-application-log:
                        type: str
                        description: 'Enable/disable logging for unknown applications.'
                        choices:
                            - 'disable'
                            - 'enable'
    schema_object1:
        methods: [get]
        description: 'Configure application control lists.'
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
                            - 'app-replacemsg'
                            - 'comment'
                            - 'deep-app-inspection'
                            - 'extended-log'
                            - 'name'
                            - 'options'
                            - 'other-application-action'
                            - 'other-application-log'
                            - 'p2p-black-list'
                            - 'replacemsg-group'
                            - 'unknown-application-action'
                            - 'unknown-application-log'
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

    - name: REQUESTING /PM/CONFIG/OBJ/APPLICATION/LIST
      fmgr_application_list:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     app-replacemsg: <value in [disable, enable]>
                     comment: <value of string>
                     deep-app-inspection: <value in [disable, enable]>
                     entries:
                       -
                           action: <value in [pass, block, reset]>
                           application:
                             - <value of integer>
                           behavior:
                             - <value of string>
                           category: <value of string>
                           id: <value of integer>
                           log: <value in [disable, enable]>
                           log-packet: <value in [disable, enable]>
                           parameters:
                             -
                                 id: <value of integer>
                                 value: <value of string>
                           per-ip-shaper: <value of string>
                           popularity:
                             - <value in [1, 2, 3, ...]>
                           protocols:
                             - <value of string>
                           quarantine: <value in [none, attacker]>
                           quarantine-expiry: <value of string>
                           quarantine-log: <value in [disable, enable]>
                           rate-count: <value of integer>
                           rate-duration: <value of integer>
                           rate-mode: <value in [periodical, continuous]>
                           rate-track: <value in [none, src-ip, dest-ip, ...]>
                           risk:
                             - <value of integer>
                           session-ttl: <value of integer>
                           shaper: <value of string>
                           shaper-reverse: <value of string>
                           sub-category:
                             - <value of integer>
                           technology:
                             - <value of string>
                           vendor:
                             - <value of string>
                     extended-log: <value in [disable, enable]>
                     name: <value of string>
                     options:
                       - <value in [allow-dns, allow-icmp, allow-http, ...]>
                     other-application-action: <value in [pass, block]>
                     other-application-log: <value in [disable, enable]>
                     p2p-black-list:
                       - <value in [skype, edonkey, bittorrent]>
                     replacemsg-group: <value of string>
                     unknown-application-action: <value in [pass, block]>
                     unknown-application-log: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/APPLICATION/LIST
      fmgr_application_list:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [app-replacemsg, comment, deep-app-inspection, ...]>
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
            example: '/pm/config/adom/{adom}/obj/application/list'
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
               app-replacemsg:
                  type: str
                  description: 'Enable/disable replacement messages for blocked applications.'
               comment:
                  type: str
                  description: 'comments'
               deep-app-inspection:
                  type: str
                  description: 'Enable/disable deep application inspection.'
               entries:
                  type: array
                  suboptions:
                     action:
                        type: str
                        description: 'Pass or block traffic, or reset connection for traffic from this application.'
                     application:
                        type: array
                        suboptions:
                           type: int
                     behavior:
                        type: array
                        suboptions:
                           type: str
                     category:
                        type: str
                        description: 'Category ID list.'
                     id:
                        type: int
                        description: 'Entry ID.'
                     log:
                        type: str
                        description: 'Enable/disable logging for this application list.'
                     log-packet:
                        type: str
                        description: 'Enable/disable packet logging.'
                     parameters:
                        type: array
                        suboptions:
                           id:
                              type: int
                              description: 'Parameter ID.'
                           value:
                              type: str
                              description: 'Parameter value.'
                     per-ip-shaper:
                        type: str
                        description: 'Per-IP traffic shaper.'
                     popularity:
                        type: array
                        suboptions:
                           type: str
                     protocols:
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
                     risk:
                        type: array
                        suboptions:
                           type: int
                     session-ttl:
                        type: int
                        description: 'Session TTL (0 = default).'
                     shaper:
                        type: str
                        description: 'Traffic shaper.'
                     shaper-reverse:
                        type: str
                        description: 'Reverse traffic shaper.'
                     sub-category:
                        type: array
                        suboptions:
                           type: int
                     technology:
                        type: array
                        suboptions:
                           type: str
                     vendor:
                        type: array
                        suboptions:
                           type: str
               extended-log:
                  type: str
                  description: 'Enable/disable extended logging.'
               name:
                  type: str
                  description: 'List name.'
               options:
                  type: array
                  suboptions:
                     type: str
               other-application-action:
                  type: str
                  description: 'Action for other applications.'
               other-application-log:
                  type: str
                  description: 'Enable/disable logging for other applications.'
               p2p-black-list:
                  type: array
                  suboptions:
                     type: str
               replacemsg-group:
                  type: str
                  description: 'Replacement message group.'
               unknown-application-action:
                  type: str
                  description: 'Pass or block traffic from unknown applications.'
               unknown-application-log:
                  type: str
                  description: 'Enable/disable logging for unknown applications.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/application/list'

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
        '/pm/config/adom/{adom}/obj/application/list',
        '/pm/config/global/obj/application/list'
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
                        'app-replacemsg': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'deep-app-inspection': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'entries': {
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
                                'application': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'integer'
                                    }
                                },
                                'behavior': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'category': {
                                    'type': 'string'
                                },
                                'id': {
                                    'type': 'integer'
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
                                'parameters': {
                                    'type': 'array',
                                    'items': {
                                        'id': {
                                            'type': 'integer'
                                        },
                                        'value': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'per-ip-shaper': {
                                    'type': 'string'
                                },
                                'popularity': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string',
                                        'enum': [
                                            '1',
                                            '2',
                                            '3',
                                            '4',
                                            '5'
                                        ]
                                    }
                                },
                                'protocols': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'quarantine': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'attacker'
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
                                'risk': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'integer'
                                    }
                                },
                                'session-ttl': {
                                    'type': 'integer'
                                },
                                'shaper': {
                                    'type': 'string'
                                },
                                'shaper-reverse': {
                                    'type': 'string'
                                },
                                'sub-category': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'integer'
                                    }
                                },
                                'technology': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'vendor': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
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
                        'name': {
                            'type': 'string'
                        },
                        'options': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'allow-dns',
                                    'allow-icmp',
                                    'allow-http',
                                    'allow-ssl',
                                    'allow-quic'
                                ]
                            }
                        },
                        'other-application-action': {
                            'type': 'string',
                            'enum': [
                                'pass',
                                'block'
                            ]
                        },
                        'other-application-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'p2p-black-list': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'skype',
                                    'edonkey',
                                    'bittorrent'
                                ]
                            }
                        },
                        'replacemsg-group': {
                            'type': 'string'
                        },
                        'unknown-application-action': {
                            'type': 'string',
                            'enum': [
                                'pass',
                                'block'
                            ]
                        },
                        'unknown-application-log': {
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
                                'app-replacemsg',
                                'comment',
                                'deep-app-inspection',
                                'extended-log',
                                'name',
                                'options',
                                'other-application-action',
                                'other-application-log',
                                'p2p-black-list',
                                'replacemsg-group',
                                'unknown-application-action',
                                'unknown-application-log'
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
