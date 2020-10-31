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
module: fmgr_system_admin_user_dashboard
short_description: Custom dashboard widgets.
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
                description: 'Widgets column ID.'
            diskio-content-type:
                type: str
                default: 'util'
                description:
                 - 'Disk I/O Monitor widgets chart type.'
                 - 'util - bandwidth utilization.'
                 - 'iops - the number of I/O requests.'
                 - 'blks - the amount of data of I/O requests.'
                choices:
                    - 'util'
                    - 'iops'
                    - 'blks'
            diskio-period:
                type: str
                default: '1hour'
                description:
                 - 'Disk I/O Monitor widgets data period.'
                 - '1hour - 1 hour.'
                 - '8hour - 8 hour.'
                 - '24hour - 24 hour.'
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            log-rate-period:
                type: str
                description:
                 - 'Log receive monitor widgets data period.'
                 - '2min  - 2 minutes.'
                 - '1hour - 1 hour.'
                 - '6hours - 6 hours.'
                choices:
                    - '2min'
                    - '1hour'
                    - '6hours'
            log-rate-topn:
                type: str
                default: '5'
                description:
                 - 'Log receive monitor widgets number of top items to display.'
                 - '1 - Top 1.'
                 - '2 - Top 2.'
                 - '3 - Top 3.'
                 - '4 - Top 4.'
                 - '5 - Top 5.'
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
                 - 'Log receive monitor widgets statistics breakdown options.'
                 - 'log - Show log rates for each log type.'
                 - 'device - Show log rates for each device.'
                choices:
                    - 'log'
                    - 'device'
            moduleid:
                type: int
                default: 0
                description: 'Widget ID.'
            name:
                type: str
                description: 'Widget name.'
            num-entries:
                type: int
                default: 10
                description: 'Number of entries.'
            refresh-interval:
                type: int
                default: 300
                description: 'Widgets refresh interval.'
            res-cpu-display:
                type: str
                default: 'average'
                description:
                 - 'Widgets CPU display type.'
                 - 'average  - Average usage of CPU.'
                 - 'each - Each usage of CPU.'
                choices:
                    - 'average'
                    - 'each'
            res-period:
                type: str
                description:
                 - 'Widgets data period.'
                 - '10min  - Last 10 minutes.'
                 - 'hour - Last hour.'
                 - 'day - Last day.'
                choices:
                    - '10min'
                    - 'hour'
                    - 'day'
            res-view-type:
                type: str
                description:
                 - 'Widgets data view type.'
                 - 'real-time  - Real-time view.'
                 - 'history - History view.'
                choices:
                    - 'real-time'
                    - 'history'
            status:
                type: str
                default: 'open'
                description:
                 - 'Widgets opened/closed state.'
                 - 'close - Widget closed.'
                 - 'open - Widget opened.'
                choices:
                    - 'close'
                    - 'open'
            tabid:
                type: int
                default: 0
                description: 'ID of tab where widget is displayed.'
            time-period:
                type: str
                default: '1hour'
                description:
                 - 'Log Database Monitor widgets data period.'
                 - '1hour - 1 hour.'
                 - '8hour - 8 hour.'
                 - '24hour - 24 hour.'
                choices:
                    - '1hour'
                    - '8hour'
                    - '24hour'
            widget-type:
                type: str
                description:
                 - 'Widget type.'
                 - 'top-lograte - Log Receive Monitor.'
                 - 'sysres - System resources.'
                 - 'sysinfo - System Information.'
                 - 'licinfo - License Information.'
                 - 'jsconsole - CLI Console.'
                 - 'sysop - Unit Operation.'
                 - 'alert - Alert Message Console.'
                 - 'statistics - Statistics.'
                 - 'rpteng - Report Engine.'
                 - 'raid - Disk Monitor.'
                 - 'logrecv - Logs/Data Received.'
                 - 'devsummary - Device Summary.'
                 - 'logdb-perf - Log Database Performance Monitor.'
                 - 'logdb-lag - Log Database Lag Time.'
                 - 'disk-io - Disk I/O.'
                 - 'log-rcvd-fwd - Log receive and forwarding Monitor.'
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
 - hosts: fortimanager-inventory
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
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         user: <your own value>
         state: <value in [present, absent]>
         system_admin_user_dashboard:
            column: <value of integer>
            diskio-content-type: <value in [util, iops, blks]>
            diskio-period: <value in [1hour, 8hour, 24hour]>
            log-rate-period: <value in [2min, 1hour, 6hours]>
            log-rate-topn: <value in [1, 2, 3, ...]>
            log-rate-type: <value in [log, device]>
            moduleid: <value of integer>
            name: <value of string>
            num-entries: <value of integer>
            refresh-interval: <value of integer>
            res-cpu-display: <value in [average, each]>
            res-period: <value in [10min, hour, day]>
            res-view-type: <value in [real-time, history]>
            status: <value in [close, open]>
            tabid: <value of integer>
            time-period: <value in [1hour, 8hour, 24hour]>
            widget-type: <value in [top-lograte, sysres, sysinfo, ...]>

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
            'options': {
                'column': {
                    'required': False,
                    'type': 'int'
                },
                'diskio-content-type': {
                    'required': False,
                    'choices': [
                        'util',
                        'iops',
                        'blks'
                    ],
                    'type': 'str'
                },
                'diskio-period': {
                    'required': False,
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
                    'choices': [
                        'log',
                        'device'
                    ],
                    'type': 'str'
                },
                'moduleid': {
                    'required': True,
                    'type': 'int'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'num-entries': {
                    'required': False,
                    'type': 'int'
                },
                'refresh-interval': {
                    'required': False,
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
                    'choices': [
                        'close',
                        'open'
                    ],
                    'type': 'str'
                },
                'tabid': {
                    'required': False,
                    'type': 'int'
                },
                'time-period': {
                    'required': False,
                    'choices': [
                        '1hour',
                        '8hour',
                        '24hour'
                    ],
                    'type': 'str'
                },
                'widget-type': {
                    'required': False,
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
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
