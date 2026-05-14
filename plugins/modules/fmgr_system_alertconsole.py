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
module: fmgr_system_alertconsole
short_description: Alert console.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_alertconsole:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            period:
                type: str
                description:
                    - Alert console keeps alerts for this period.
                    - 1 - 1 day.
                    - 2 - 2 days.
                    - 3 - 3 days.
                    - 4 - 4 days.
                    - 5 - 5 days.
                    - 6 - 6 days.
                    - 7 - 7 days.
                choices: ['1', '2', '3', '4', '5', '6', '7']
            severity_level:
                aliases: ['severity-level']
                type: list
                elements: str
                description:
                    - Alert console keeps alerts of this and higher severity.
                    - debug - Debug level.
                    - information - Information level.
                    - notify - Notify level.
                    - warning - Warning level.
                    - error - Error level.
                    - critical - Critical level.
                    - alert - Alert level.
                    - emergency - Emergency level.
                choices: ['debug', 'information', 'notify', 'warning', 'error', 'critical',
                          'alert', 'emergency']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Alert console.
      fortinet.fortimanager.fmgr_system_alertconsole:
        # workspace_locking_adom: <global or your adom name>
        system_alertconsole:
          # period: <value in [1, 2, 3, ...]>
          # severity_level: ["debug", "information", "notify", "warning", "error", "critical",
          #                  "alert", "emergency"]
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
        '/cli/global/system/alert-console'
    ]
    module_arg_spec = {
        'system_alertconsole': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'period': {'choices': ['1', '2', '3', '4', '5', '6', '7'], 'type': 'str'},
                'severity-level': {
                    'type': 'list',
                    'choices': ['debug', 'information', 'notify', 'warning', 'error', 'critical', 'alert', 'emergency'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_alertconsole'),
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
