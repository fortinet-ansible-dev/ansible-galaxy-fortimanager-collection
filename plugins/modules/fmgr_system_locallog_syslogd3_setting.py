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
module: fmgr_system_locallog_syslogd3_setting
short_description: Settings for remote syslog server.
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
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
    system_locallog_syslogd3_setting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            csv:
                type: str
                default: 'disable'
                description:
                 - 'CSV format.'
                 - 'disable - Disable CSV format.'
                 - 'enable - Enable CSV format.'
                choices:
                    - 'disable'
                    - 'enable'
            facility:
                type: str
                default: 'local7'
                description:
                 - 'Remote syslog facility.'
                 - 'kernel - Kernel messages.'
                 - 'user - Random user-level messages.'
                 - 'ntp - NTP daemon.'
                 - 'audit - Log audit.'
                 - 'alert - Log alert.'
                 - 'clock - Clock daemon.'
                 - 'mail - Mail system.'
                 - 'daemon - System daemons.'
                 - 'auth - Security/authorization messages.'
                 - 'syslog - Messages generated internally by syslog daemon.'
                 - 'lpr - Line printer subsystem.'
                 - 'news - Network news subsystem.'
                 - 'uucp - Network news subsystem.'
                 - 'cron - Clock daemon.'
                 - 'authpriv - Security/authorization messages (private).'
                 - 'ftp - FTP daemon.'
                 - 'local0 - Reserved for local use.'
                 - 'local1 - Reserved for local use.'
                 - 'local2 - Reserved for local use.'
                 - 'local3 - Reserved for local use.'
                 - 'local4 - Reserved for local use.'
                 - 'local5 - Reserved for local use.'
                 - 'local6 - Reserved for local use.'
                 - 'local7 - Reserved for local use.'
                choices:
                    - 'kernel'
                    - 'user'
                    - 'ntp'
                    - 'audit'
                    - 'alert'
                    - 'clock'
                    - 'mail'
                    - 'daemon'
                    - 'auth'
                    - 'syslog'
                    - 'lpr'
                    - 'news'
                    - 'uucp'
                    - 'cron'
                    - 'authpriv'
                    - 'ftp'
                    - 'local0'
                    - 'local1'
                    - 'local2'
                    - 'local3'
                    - 'local4'
                    - 'local5'
                    - 'local6'
                    - 'local7'
            severity:
                type: str
                default: 'notification'
                description:
                 - 'Least severity level to log.'
                 - 'emergency - Emergency level.'
                 - 'alert - Alert level.'
                 - 'critical - Critical level.'
                 - 'error - Error level.'
                 - 'warning - Warning level.'
                 - 'notification - Notification level.'
                 - 'information - Information level.'
                 - 'debug - Debug level.'
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            status:
                type: str
                default: 'disable'
                description:
                 - 'Remote syslog log.'
                 - 'disable - Do not log to remote syslog server.'
                 - 'enable - Log to remote syslog server.'
                choices:
                    - 'disable'
                    - 'enable'
            syslog-name:
                type: str
                description: 'Remote syslog server name.'

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
    - name: Settings for remote syslog server.
      fmgr_system_locallog_syslogd3_setting:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         system_locallog_syslogd3_setting:
            csv: <value in [disable, enable]>
            facility: <value in [kernel, user, ntp, ...]>
            severity: <value in [emergency, alert, critical, ...]>
            status: <value in [disable, enable]>
            syslog-name: <value of string>

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
        '/cli/global/system/locallog/syslogd3/setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/locallog/syslogd3/setting/{setting}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'system_locallog_syslogd3_setting': {
            'required': False,
            'type': 'dict',
            'options': {
                'csv': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'facility': {
                    'required': False,
                    'choices': [
                        'kernel',
                        'user',
                        'ntp',
                        'audit',
                        'alert',
                        'clock',
                        'mail',
                        'daemon',
                        'auth',
                        'syslog',
                        'lpr',
                        'news',
                        'uucp',
                        'cron',
                        'authpriv',
                        'ftp',
                        'local0',
                        'local1',
                        'local2',
                        'local3',
                        'local4',
                        'local5',
                        'local6',
                        'local7'
                    ],
                    'type': 'str'
                },
                'severity': {
                    'required': False,
                    'choices': [
                        'emergency',
                        'alert',
                        'critical',
                        'error',
                        'warning',
                        'notification',
                        'information',
                        'debug'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'syslog-name': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_locallog_syslogd3_setting'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
