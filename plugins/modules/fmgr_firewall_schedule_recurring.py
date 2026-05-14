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
module: fmgr_firewall_schedule_recurring
short_description: Recurring schedule configuration.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    firewall_schedule_recurring:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            color:
                type: int
                description: Color of icon on the GUI.
            day:
                type: list
                elements: str
                description: One or more days of the week on which the schedule is valid.
                choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                          'saturday', 'none']
            end:
                type: str
                description: Time of day to end the schedule, format hh
            name:
                type: str
                description: Recurring schedule name.
                required: true
            start:
                type: str
                description: Time of day to start the schedule, format hh
            global_object:
                aliases: ['global-object']
                type: int
                description: Global Object.
            fabric_object:
                aliases: ['fabric-object']
                type: str
                description: Security Fabric global object setting.
                choices: ['disable', 'enable']
            uuid:
                type: str
                description: Universally Unique Identifier
            label_day:
                aliases: ['label-day']
                type: str
                description: Configure a window during the time of day in which the schedule job is executed.
                choices: ['none', 'over-night', 'early-morning', 'morning', 'midday', 'afternoon',
                          'evening', 'night', 'late-night']
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
    - name: Recurring schedule configuration.
      fortinet.fortimanager.fmgr_firewall_schedule_recurring:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_schedule_recurring:
          color: 1
          day:
            - sunday
            - monday
            - tuesday
            - wednesday
            - thursday
            - friday
            - saturday
            - none
          end: "15:00"
          name: "ansible-test-recurring"
          start: "07:00"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the recurring schedles
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_schedule_recurring"
          params:
            adom: "ansible"
            recurring: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/schedule/recurring',
        '/pm/config/global/obj/firewall/schedule/recurring'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_schedule_recurring': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'color': {'type': 'int'},
                'day': {
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'none'],
                    'elements': 'str'
                },
                'end': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'start': {'type': 'str'},
                'global-object': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'fabric-object': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'label-day': {
                    'v_range': [['7.6.5', '']],
                    'choices': ['none', 'over-night', 'early-morning', 'morning', 'midday', 'afternoon', 'evening', 'night', 'late-night'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_schedule_recurring'),
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
