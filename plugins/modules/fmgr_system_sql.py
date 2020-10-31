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
module: fmgr_system_sql
short_description: SQL settings.
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
    system_sql:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            background-rebuild:
                type: str
                default: 'enable'
                description:
                 - 'Disable/Enable rebuild SQL database in the background.'
                 - 'disable - Rebuild SQL database not in the background.'
                 - 'enable - Rebuild SQL database in the background.'
                choices:
                    - 'disable'
                    - 'enable'
            custom-index:
                description: no description
                type: list
                suboptions:
                    case-sensitive:
                        type: str
                        default: 'disable'
                        description:
                         - 'Disable/Enable case sensitive index.'
                         - 'disable - Build a case insensitive index.'
                         - 'enable - Build a case sensitive index.'
                        choices:
                            - 'disable'
                            - 'enable'
                    device-type:
                        type: str
                        default: 'FortiGate'
                        description:
                         - 'Device type.'
                         - 'FortiGate - Device type to FortiGate.'
                         - 'FortiManager - Set device type to FortiManager'
                         - 'FortiClient - Set device type to FortiClient'
                         - 'FortiMail - Device type to FortiMail.'
                         - 'FortiWeb - Device type to FortiWeb.'
                         - 'FortiCache - Set device type to FortiCache'
                         - 'FortiSandbox - Set device type to FortiSandbox'
                         - 'FortiDDoS - Set device type to FortiDDoS'
                         - 'FortiAuthenticator - Set device type to FortiAuthenticator'
                         - 'FortiProxy - Set device type to FortiProxy'
                        choices:
                            - 'FortiGate'
                            - 'FortiManager'
                            - 'FortiClient'
                            - 'FortiMail'
                            - 'FortiWeb'
                            - 'FortiCache'
                            - 'FortiSandbox'
                            - 'FortiDDoS'
                            - 'FortiAuthenticator'
                            - 'FortiProxy'
                    id:
                        type: int
                        default: 0
                        description: 'Add or Edit log index fields.'
                    index-field:
                        type: str
                        description: 'Log field name to be indexed.'
                    log-type:
                        type: str
                        default: 'traffic'
                        description:
                         - 'Log type.'
                         - 'none - none'
                         - 'app-ctrl '
                         - 'attack '
                         - 'content '
                         - 'dlp '
                         - 'emailfilter '
                         - 'event '
                         - 'generic '
                         - 'history '
                         - 'traffic '
                         - 'virus '
                         - 'voip '
                         - 'webfilter '
                         - 'netscan '
                         - 'fct-event '
                         - 'fct-traffic '
                         - 'fct-netscan '
                         - 'waf '
                         - 'gtp '
                         - 'dns '
                         - 'ssh '
                         - 'ssl '
                        choices:
                            - 'none'
                            - 'app-ctrl'
                            - 'attack'
                            - 'content'
                            - 'dlp'
                            - 'emailfilter'
                            - 'event'
                            - 'generic'
                            - 'history'
                            - 'traffic'
                            - 'virus'
                            - 'voip'
                            - 'webfilter'
                            - 'netscan'
                            - 'fct-event'
                            - 'fct-traffic'
                            - 'fct-netscan'
                            - 'waf'
                            - 'gtp'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
            database-name:
                type: str
                description: 'Database name.'
            database-type:
                type: str
                default: 'postgres'
                description:
                 - 'Database type.'
                 - 'mysql - MySQL database.'
                 - 'postgres - PostgreSQL local database.'
                choices:
                    - 'mysql'
                    - 'postgres'
            device-count-high:
                type: str
                default: 'disable'
                description:
                 - 'Must set to enable if the count of registered devices is greater than 8000.'
                 - 'disable - Set to disable if device count is less than 8000.'
                 - 'enable - Set to enable if device count is equal to or greater than 8000.'
                choices:
                    - 'disable'
                    - 'enable'
            event-table-partition-time:
                type: int
                default: 0
                description: 'Maximum SQL database table partitioning time range in minute (0 for unlimited) for event logs.'
            fct-table-partition-time:
                type: int
                default: 240
                description: 'Maximum SQL database table partitioning time range in minute (0 for unlimited) for FortiClient logs.'
            logtype:
                description: no description
                type: list
                choices:
                 - none
                 - app-ctrl
                 - attack
                 - content
                 - dlp
                 - emailfilter
                 - event
                 - generic
                 - history
                 - traffic
                 - virus
                 - voip
                 - webfilter
                 - netscan
                 - fct-event
                 - fct-traffic
                 - fct-netscan
                 - waf
                 - gtp
                 - dns
                 - ssh
                 - ssl
            password:
                description: no description
                type: str
            prompt-sql-upgrade:
                type: str
                default: 'enable'
                description:
                 - 'Prompt to convert log database into SQL database at start time on GUI.'
                 - 'disable - Do not prompt to upgrade log database to SQL database at start time on GUI.'
                 - 'enable - Prompt to upgrade log database to SQL database at start time on GUI.'
                choices:
                    - 'disable'
                    - 'enable'
            rebuild-event:
                type: str
                default: 'enable'
                description:
                 - 'Disable/Enable rebuild event during SQL database rebuilding.'
                 - 'disable - Do not rebuild event during SQL database rebuilding.'
                 - 'enable - Rebuild event during SQL database rebuilding.'
                choices:
                    - 'disable'
                    - 'enable'
            rebuild-event-start-time:
                description: no description
                type: str
            server:
                type: str
                description: 'Database IP or hostname.'
            start-time:
                description: no description
                type: str
            status:
                type: str
                default: 'local'
                description:
                 - 'SQL database status.'
                 - 'disable - Disable SQL database.'
                 - 'local - Enable local database.'
                choices:
                    - 'disable'
                    - 'local'
            text-search-index:
                type: str
                default: 'disable'
                description:
                 - 'Disable/Enable text search index.'
                 - 'disable - Do not create text search index.'
                 - 'enable - Create text search index.'
                choices:
                    - 'disable'
                    - 'enable'
            traffic-table-partition-time:
                type: int
                default: 0
                description: 'Maximum SQL database table partitioning time range in minute (0 for unlimited) for traffic logs.'
            ts-index-field:
                description: no description
                type: list
                suboptions:
                    category:
                        type: str
                        description: 'Category of text search index fields.'
                    value:
                        type: str
                        description: 'Fields of text search index.'
            username:
                type: str
                description: 'User name for login remote database.'
            utm-table-partition-time:
                type: int
                default: 0
                description: 'Maximum SQL database table partitioning time range in minute (0 for unlimited) for UTM logs.'

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
    - name: SQL settings.
      fmgr_system_sql:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         system_sql:
            background-rebuild: <value in [disable, enable]>
            custom-index:
              -
                  case-sensitive: <value in [disable, enable]>
                  device-type: <value in [FortiGate, FortiManager, FortiClient, ...]>
                  id: <value of integer>
                  index-field: <value of string>
                  log-type: <value in [none, app-ctrl, attack, ...]>
            database-name: <value of string>
            database-type: <value in [mysql, postgres]>
            device-count-high: <value in [disable, enable]>
            event-table-partition-time: <value of integer>
            fct-table-partition-time: <value of integer>
            logtype:
              - none
              - app-ctrl
              - attack
              - content
              - dlp
              - emailfilter
              - event
              - generic
              - history
              - traffic
              - virus
              - voip
              - webfilter
              - netscan
              - fct-event
              - fct-traffic
              - fct-netscan
              - waf
              - gtp
              - dns
              - ssh
              - ssl
            password: <value of string>
            prompt-sql-upgrade: <value in [disable, enable]>
            rebuild-event: <value in [disable, enable]>
            rebuild-event-start-time: <value of string>
            server: <value of string>
            start-time: <value of string>
            status: <value in [disable, local]>
            text-search-index: <value in [disable, enable]>
            traffic-table-partition-time: <value of integer>
            ts-index-field:
              -
                  category: <value of string>
                  value: <value of string>
            username: <value of string>
            utm-table-partition-time: <value of integer>

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
        '/cli/global/system/sql'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/sql/{sql}'
    ]

    url_params = []
    module_primary_key = None
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
        'system_sql': {
            'required': False,
            'type': 'dict',
            'options': {
                'background-rebuild': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'custom-index': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'case-sensitive': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'device-type': {
                            'required': False,
                            'choices': [
                                'FortiGate',
                                'FortiManager',
                                'FortiClient',
                                'FortiMail',
                                'FortiWeb',
                                'FortiCache',
                                'FortiSandbox',
                                'FortiDDoS',
                                'FortiAuthenticator',
                                'FortiProxy'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'index-field': {
                            'required': False,
                            'type': 'str'
                        },
                        'log-type': {
                            'required': False,
                            'choices': [
                                'none',
                                'app-ctrl',
                                'attack',
                                'content',
                                'dlp',
                                'emailfilter',
                                'event',
                                'generic',
                                'history',
                                'traffic',
                                'virus',
                                'voip',
                                'webfilter',
                                'netscan',
                                'fct-event',
                                'fct-traffic',
                                'fct-netscan',
                                'waf',
                                'gtp',
                                'dns',
                                'ssh',
                                'ssl'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'database-name': {
                    'required': False,
                    'type': 'str'
                },
                'database-type': {
                    'required': False,
                    'choices': [
                        'mysql',
                        'postgres'
                    ],
                    'type': 'str'
                },
                'device-count-high': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'event-table-partition-time': {
                    'required': False,
                    'type': 'int'
                },
                'fct-table-partition-time': {
                    'required': False,
                    'type': 'int'
                },
                'logtype': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'none',
                        'app-ctrl',
                        'attack',
                        'content',
                        'dlp',
                        'emailfilter',
                        'event',
                        'generic',
                        'history',
                        'traffic',
                        'virus',
                        'voip',
                        'webfilter',
                        'netscan',
                        'fct-event',
                        'fct-traffic',
                        'fct-netscan',
                        'waf',
                        'gtp',
                        'dns',
                        'ssh',
                        'ssl'
                    ]
                },
                'password': {
                    'required': False,
                    'type': 'str'
                },
                'prompt-sql-upgrade': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rebuild-event': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rebuild-event-start-time': {
                    'required': False,
                    'type': 'str'
                },
                'server': {
                    'required': False,
                    'type': 'str'
                },
                'start-time': {
                    'required': False,
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'local'
                    ],
                    'type': 'str'
                },
                'text-search-index': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'traffic-table-partition-time': {
                    'required': False,
                    'type': 'int'
                },
                'ts-index-field': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'category': {
                            'required': False,
                            'type': 'str'
                        },
                        'value': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'username': {
                    'required': False,
                    'type': 'str'
                },
                'utm-table-partition-time': {
                    'required': False,
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sql'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
