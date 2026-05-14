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
module: fmgr_system_alertevent
short_description: Alert events.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_alertevent:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            alert_destination:
                aliases: ['alert-destination']
                type: list
                elements: dict
                description: Alert destination.
                suboptions:
                    from:
                        type: str
                        description: Sender email address to use in alert emails.
                    smtp_name:
                        aliases: ['smtp-name']
                        type: str
                        description: SMTP server name.
                    snmp_name:
                        aliases: ['snmp-name']
                        type: str
                        description: SNMP trap name.
                    syslog_name:
                        aliases: ['syslog-name']
                        type: str
                        description: Syslog server name.
                    to:
                        type: str
                        description: Recipient email address to use in alert emails.
                    type:
                        type: str
                        description:
                            - Destination type.
                            - mail - Send email alert.
                            - snmp - Send SNMP trap.
                            - syslog - Send syslog message.
                        choices: ['mail', 'snmp', 'syslog']
            enable_generic_text:
                aliases: ['enable-generic-text']
                type: list
                elements: str
                description:
                    - Enable/disable generic text match.
                    - enable - Enable setting.
                    - disable - Disable setting.
                choices: ['enable', 'disable']
            enable_severity_filter:
                aliases: ['enable-severity-filter']
                type: list
                elements: str
                description:
                    - Enable/disable alert severity filter.
                    - enable - Enable setting.
                    - disable - Disable setting.
                choices: ['enable', 'disable']
            event_time_period:
                aliases: ['event-time-period']
                type: str
                description:
                    - Time period
                    - '0.'
                    - 1 - 1 hour.
                    - 3 - 3 hours.
                    - 6 - 6 hours.
                    - 12 - 12 hours.
                    - 24 - 1 day.
                    - 72 - 3 days.
                    - 168 - 1 week.
                choices: ['0.5', '1', '3', '6', '12', '24', '72', '168']
            generic_text:
                aliases: ['generic-text']
                type: str
                description: Text that must be contained in a log to trigger alert.
            name:
                type: str
                description: Alert name.
                required: true
            num_events:
                aliases: ['num-events']
                type: str
                description:
                    - Minimum number of events required within time period.
                    - 1 - 1 event.
                    - 5 - 5 events.
                    - 10 - 10 events.
                    - 50 - 50 events.
                    - 100 - 100 events.
                choices: ['1', '5', '10', '50', '100']
            severity_filter:
                aliases: ['severity-filter']
                type: str
                description:
                    - Required log severity to trigger alert.
                    - high - High level alert.
                    - medium-high - Medium-high level alert.
                    - medium - Medium level alert.
                    - medium-low - Medium-low level alert.
                    - low - Low level alert.
                choices: ['high', 'medium-high', 'medium', 'medium-low', 'low']
            severity_level_comp:
                aliases: ['severity-level-comp']
                type: list
                elements: str
                description: Log severity threshold comparison criterion.
                choices: ['>=', '=', '<=']
            severity_level_logs:
                aliases: ['severity-level-logs']
                type: list
                elements: str
                description:
                    - Log severity threshold level.
                    - no-check - Do not check severity level for this log type.
                    - information - Information level.
                    - notify - Notify level.
                    - warning - Warning level.
                    - error - Error level.
                    - critical - Critical level.
                    - alert - Alert level.
                    - emergency - Emergency level.
                choices: ['no-check', 'information', 'notify', 'warning', 'error', 'critical',
                          'alert', 'emergency']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Alert events.
      fortinet.fortimanager.fmgr_system_alertevent:
        bypass_validation: false
        state: present
        system_alertevent:
          enable_generic_text:
            - enable
            - disable
          enable_severity_filter:
            - enable
            - disable
          event_time_period: 1 # <value in [0.5, 1, 3, ...]>
          name: ansible-test-sysalert
          num_events: 1 # <value in [1, 5, 10, ...]>
          severity_filter: high # <value in [high, medium-high, medium, ...]>
          # severity_level_comp:
          #  - <=
          severity_level_logs:
            - no-check
            - information
            - notify
            - warning
            - error
            - critical
            - alert
            - emergency

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the alert events
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_alertevent"
          params:
            alert_event: "your_value"
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
        '/cli/global/system/alert-event'
    ]
    module_arg_spec = {
        'system_alertevent': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'alert-destination': {
                    'type': 'list',
                    'options': {
                        'from': {'type': 'str'},
                        'smtp-name': {'type': 'str'},
                        'snmp-name': {'type': 'str'},
                        'syslog-name': {'type': 'str'},
                        'to': {'type': 'str'},
                        'type': {'choices': ['mail', 'snmp', 'syslog'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enable-generic-text': {'type': 'list', 'choices': ['enable', 'disable'], 'elements': 'str'},
                'enable-severity-filter': {'type': 'list', 'choices': ['enable', 'disable'], 'elements': 'str'},
                'event-time-period': {'choices': ['0.5', '1', '3', '6', '12', '24', '72', '168'], 'type': 'str'},
                'generic-text': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'num-events': {'choices': ['1', '5', '10', '50', '100'], 'type': 'str'},
                'severity-filter': {'choices': ['high', 'medium-high', 'medium', 'medium-low', 'low'], 'type': 'str'},
                'severity-level-comp': {'type': 'list', 'choices': ['>=', '=', '<='], 'elements': 'str'},
                'severity-level-logs': {
                    'type': 'list',
                    'choices': ['no-check', 'information', 'notify', 'warning', 'error', 'critical', 'alert', 'emergency'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_alertevent'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
