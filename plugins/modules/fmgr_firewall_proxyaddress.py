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
module: fmgr_firewall_proxyaddress
short_description: Web proxy address configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    firewall_proxyaddress:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            case-sensitivity:
                type: str
                description: 'Enable to make the pattern case sensitive.'
                choices:
                    - 'disable'
                    - 'enable'
            category:
                type: str
                description: 'FortiGuard category ID.'
            color:
                type: int
                description: 'Integer value to determine the color of the icon in the GUI (1 - 32, default = 0, which sets value to 1).'
            comment:
                type: str
                description: 'Optional comments.'
            header:
                type: str
                description: 'HTTP header name as a regular expression.'
            header-group:
                description: no description
                type: list
                suboptions:
                    case-sensitivity:
                        type: str
                        description: 'Case sensitivity in pattern.'
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: 'HTTP header regular expression.'
                    header-name:
                        type: str
                        description: 'HTTP header.'
                    id:
                        type: int
                        description: 'ID.'
            header-name:
                type: str
                description: 'Name of HTTP header.'
            host:
                type: str
                description: 'Address object for the host.'
            host-regex:
                type: str
                description: 'Host name as a regular expression.'
            method:
                description: no description
                type: list
                choices:
                 - delete
                 - get
                 - head
                 - options
                 - post
                 - put
                 - trace
                 - connect
            name:
                type: str
                description: 'Address name.'
            path:
                type: str
                description: 'URL path as a regular expression.'
            query:
                type: str
                description: 'Match the query part of the URL as a regular expression.'
            referrer:
                type: str
                description: 'Enable/disable use of referrer field in the HTTP header to match the address.'
                choices:
                    - 'disable'
                    - 'enable'
            tagging:
                description: no description
                type: list
                suboptions:
                    category:
                        type: str
                        description: 'Tag category.'
                    name:
                        type: str
                        description: 'Tagging entry name.'
                    tags:
                        description: no description
                        type: str
            type:
                type: str
                description: 'Proxy address type.'
                choices:
                    - 'host-regex'
                    - 'url'
                    - 'category'
                    - 'method'
                    - 'ua'
                    - 'header'
                    - 'src-advanced'
                    - 'dst-advanced'
            ua:
                description: no description
                type: list
                choices:
                 - chrome
                 - ms
                 - firefox
                 - safari
                 - other
            uuid:
                type: str
                description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
            visibility:
                type: str
                description: 'Enable/disable visibility of the object in the GUI.'
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
    - name: Web proxy address configuration.
      fmgr_firewall_proxyaddress:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_proxyaddress:
            case-sensitivity: <value in [disable, enable]>
            category: <value of string>
            color: <value of integer>
            comment: <value of string>
            header: <value of string>
            header-group:
              -
                  case-sensitivity: <value in [disable, enable]>
                  header: <value of string>
                  header-name: <value of string>
                  id: <value of integer>
            header-name: <value of string>
            host: <value of string>
            host-regex: <value of string>
            method:
              - delete
              - get
              - head
              - options
              - post
              - put
              - trace
              - connect
            name: <value of string>
            path: <value of string>
            query: <value of string>
            referrer: <value in [disable, enable]>
            tagging:
              -
                  category: <value of string>
                  name: <value of string>
                  tags: <value of string>
            type: <value in [host-regex, url, category, ...]>
            ua:
              - chrome
              - ms
              - firefox
              - safari
              - other
            uuid: <value of string>
            visibility: <value in [disable, enable]>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/proxy-address',
        '/pm/config/global/obj/firewall/proxy-address'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
        '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'bypass_validation': {
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
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'firewall_proxyaddress': {
            'required': False,
            'type': 'dict',
            'options': {
                'case-sensitivity': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'category': {
                    'required': False,
                    'type': 'str'
                },
                'color': {
                    'required': False,
                    'type': 'int'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'header': {
                    'required': False,
                    'type': 'str'
                },
                'header-group': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'case-sensitivity': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'type': 'str'
                        },
                        'header-name': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'header-name': {
                    'required': False,
                    'type': 'str'
                },
                'host': {
                    'required': False,
                    'type': 'str'
                },
                'host-regex': {
                    'required': False,
                    'type': 'str'
                },
                'method': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'delete',
                        'get',
                        'head',
                        'options',
                        'post',
                        'put',
                        'trace',
                        'connect'
                    ]
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'path': {
                    'required': False,
                    'type': 'str'
                },
                'query': {
                    'required': False,
                    'type': 'str'
                },
                'referrer': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tagging': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'category': {
                            'required': False,
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'tags': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'type': {
                    'required': False,
                    'choices': [
                        'host-regex',
                        'url',
                        'category',
                        'method',
                        'ua',
                        'header',
                        'src-advanced',
                        'dst-advanced'
                    ],
                    'type': 'str'
                },
                'ua': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'chrome',
                        'ms',
                        'firefox',
                        'safari',
                        'other'
                    ]
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'visibility': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_proxyaddress'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
