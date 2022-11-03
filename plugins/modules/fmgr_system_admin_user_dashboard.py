#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
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
module: fmgr_system_admin_user_dashboard
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    user:
        description: the parameter (user) in requested url
        type: str
        required: true
    system_admin_user_dashboard:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            column:
                type: int
                default: 0
                description: no description
            diskio-content-type:
                type: str
                default: 'util'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'util'
                    - 'iops'
                    - 'blks'
            diskio-period:
                type: str
                default: '1hour'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            log-rate-period:
                type: str
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '2min'
                    - '1hour'
                    - '6hours'
            log-rate-topn:
                type: str
                default: '5'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
            log-rate-type:
                type: str
                default: 'device'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'log'
                    - 'device'
            moduleid:
                type: int
                default: 0
                description: no description
            name:
                type: str
                description: no description
            num-entries:
                type: int
                default: 10
                description: no description
            refresh-interval:
                type: int
                default: 300
                description: no description
            res-cpu-display:
                type: str
                default: 'average'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'average'
                    - 'each'
            res-period:
                type: str
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '10min'
                    - 'hour'
                    - 'day'
            res-view-type:
                type: str
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'real-time'
                    - 'history'
            status:
                type: str
                default: 'open'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'close'
                    - 'open'
            tabid:
                type: int
                default: 0
                description: no description
            time-period:
                type: str
                default: '1hour'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            widget-type:
                type: str
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'top-lograte'
                    - 'sysres'
                    - 'sysinfo'
                    - 'licinfo'
                    - 'jsconsole'
                    - 'sysop'
                    - 'alert'
                    - 'statistics'
                    - 'rpteng'
                    - 'raid'
                    - 'logrecv'
                    - 'devsummary'
                    - 'logdb-perf'
                    - 'logdb-lag'
                    - 'disk-io'
                    - 'log-rcvd-fwd'

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Custom dashboard widgets.
      fmgr_system_admin_user_dashboard:
         bypass_validation: False
         user: ansible-test
         state: present
         system_admin_user_dashboard:
            column: 1
            diskio-content-type: util #<value in [util, iops, blks]>
            diskio-period: 1hour #<value in [1hour, 8hour, 24hour]>
            log-rate-period: 1hour #<value in [2min , 1hour, 6hours]>
            log-rate-topn: 5 #<value in [1, 2, 3, ...]>
            log-rate-type: device #<value in [log, device]>
            moduleid: 10
            name: ansible-test-dashboard
            num-entries: 10
            refresh-interval: 0
            res-cpu-display: 'each' #<value in [average , each]>
            res-period: 10min #<value in [10min , hour, day]>
            res-view-type: history #<value in [real-time , history]>
            status: open #<value in [close, open]>
            tabid: 1
            time-period: 1hour #<value in [1hour, 8hour, 24hour]>
            widget-type: sysres #<value in [top-lograte, sysres, sysinfo, ...]>
 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the dashboard widgets
      fmgr_fact:
        facts:
            selector: 'system_admin_user_dashboard'
            params:
                user: 'ansible-test'
                dashboard: 'your_value'
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
        '/cli/global/system/admin/user/{user}/dashboard'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
    ]

    url_params = ['user']
    module_primary_key = 'moduleid'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
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
        'user': {
            'required': True,
            'type': 'str'
        },
        'system_admin_user_dashboard': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'column': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'diskio-content-type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'util',
                        'iops',
                        'blks'
                    ],
                    'type': 'str'
                },
                'diskio-period': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '1hour',
                        '8hour',
                        '24hour'
                    ],
                    'type': 'str'
                },
                'log-rate-period': {
                    'required': False,
                    'choices': [
                        '2min',
                        '1hour',
                        '6hours'
                    ],
                    'type': 'str'
                },
                'log-rate-topn': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '1',
                        '2',
                        '3',
                        '4',
                        '5'
                    ],
                    'type': 'str'
                },
                'log-rate-type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'log',
                        'device'
                    ],
                    'type': 'str'
                },
                'moduleid': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'name': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'num-entries': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'refresh-interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'res-cpu-display': {
                    'required': False,
                    'choices': [
                        'average',
                        'each'
                    ],
                    'type': 'str'
                },
                'res-period': {
                    'required': False,
                    'choices': [
                        '10min',
                        'hour',
                        'day'
                    ],
                    'type': 'str'
                },
                'res-view-type': {
                    'required': False,
                    'choices': [
                        'real-time',
                        'history'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'close',
                        'open'
                    ],
                    'type': 'str'
                },
                'tabid': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'time-period': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '1hour',
                        '8hour',
                        '24hour'
                    ],
                    'type': 'str'
                },
                'widget-type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'top-lograte',
                        'sysres',
                        'sysinfo',
                        'licinfo',
                        'jsconsole',
                        'sysop',
                        'alert',
                        'statistics',
                        'rpteng',
                        'raid',
                        'logrecv',
                        'devsummary',
                        'logdb-perf',
                        'logdb-lag',
                        'disk-io',
                        'log-rcvd-fwd'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_user_dashboard'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
