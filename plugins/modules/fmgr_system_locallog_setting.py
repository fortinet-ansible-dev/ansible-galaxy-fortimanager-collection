#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_locallog_setting
short_description: Settings for locallog logging.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_locallog_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            log_interval_dev_no_logging:
                aliases: ['log-interval-dev-no-logging']
                type: int
                description: Interval in minute for logging the event of no logs received from a device.
            log_interval_disk_full:
                aliases: ['log-interval-disk-full']
                type: int
                description: Interval in minute for logging the event of disk full.
            log_interval_gbday_exceeded:
                aliases: ['log-interval-gbday-exceeded']
                type: int
                description: Interval in minute for logging the event of the GB/Day license exceeded.
            log_daemon_crash:
                aliases: ['log-daemon-crash']
                type: str
                description:
                    - Send a logmsg when a daemon crashes.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            no_log_detection_threshold:
                aliases: ['no-log-detection-threshold']
                type: int
                description: Time interval in minutes to trigger a local event message if no log data is received.
            log_interval_adom_perf_stats:
                aliases: ['log-interval-adom-perf-stats']
                type: int
                description: Interval in minute for logging the event of adom perf stats.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Settings for locallog logging.
      fortinet.fortimanager.fmgr_system_locallog_setting:
        # workspace_locking_adom: <global or your adom name>
        system_locallog_setting:
          # log_interval_dev_no_logging: <integer>
          # log_interval_disk_full: <integer>
          # log_interval_gbday_exceeded: <integer>
          # log_daemon_crash: <value in [disable, enable]>
          # no_log_detection_threshold: <integer>
          # log_interval_adom_perf_stats: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/cli/global/system/locallog/setting'
    ]
    module_arg_spec = {
        'system_locallog_setting': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'log-interval-dev-no-logging': {'type': 'int'},
                'log-interval-disk-full': {'type': 'int'},
                'log-interval-gbday-exceeded': {'type': 'int'},
                'log-daemon-crash': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'no-log-detection-threshold': {'v_range': [['7.2.4', '7.2.12'], ['7.4.2', '']], 'type': 'int'},
                'log-interval-adom-perf-stats': {'v_range': [['7.4.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_locallog_setting'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
