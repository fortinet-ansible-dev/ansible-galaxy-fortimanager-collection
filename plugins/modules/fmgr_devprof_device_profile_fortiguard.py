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
module: fmgr_devprof_device_profile_fortiguard
short_description: System template device profile fortiguard
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_device_profile_fortiguard:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            target:
                type: str
                description: Target.
                choices: ['none', 'direct', 'this-fmg']
            target_ip:
                aliases: ['target-ip']
                type: str
                description: Target ip.
            auto_firmware_upgrade:
                aliases: ['auto-firmware-upgrade']
                type: str
                description: Auto firmware upgrade.
                choices: ['disable', 'enable']
            auto_firmware_upgrade_day:
                aliases: ['auto-firmware-upgrade-day']
                type: list
                elements: str
                description: Auto firmware upgrade day.
                choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                          'saturday']
            auto_firmware_upgrade_delay:
                aliases: ['auto-firmware-upgrade-delay']
                type: int
                description: Auto firmware upgrade delay.
            auto_firmware_upgrade_end_hour:
                aliases: ['auto-firmware-upgrade-end-hour']
                type: int
                description: Auto firmware upgrade end hour.
            auto_firmware_upgrade_start_hour:
                aliases: ['auto-firmware-upgrade-start-hour']
                type: int
                description: Auto firmware upgrade start hour.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: Vrf select.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: System template device profile fortiguard
      fortinet.fortimanager.fmgr_devprof_device_profile_fortiguard:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        devprof_device_profile_fortiguard:
          # target: <value in [none, direct, this-fmg]>
          # target_ip: <string>
          # auto_firmware_upgrade: <value in [disable, enable]>
          # auto_firmware_upgrade_day: ["sunday", "monday", "tuesday", "wednesday", "thursday",
          #                             "friday", "saturday"]
          # auto_firmware_upgrade_delay: <integer>
          # auto_firmware_upgrade_end_hour: <integer>
          # auto_firmware_upgrade_start_hour: <integer>
          # vrf_select: <integer>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/device/profile/fortiguard'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_device_profile_fortiguard': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'target': {'choices': ['none', 'direct', 'this-fmg'], 'type': 'str'},
                'target-ip': {'type': 'str'},
                'auto-firmware-upgrade': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-firmware-upgrade-day': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'auto-firmware-upgrade-delay': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'auto-firmware-upgrade-end-hour': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'auto-firmware-upgrade-start-hour': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_device_profile_fortiguard'),
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
