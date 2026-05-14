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
module: fmgr_system_snmp_sysinfo
short_description: SNMP configuration.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_snmp_sysinfo:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            contact_info:
                type: str
                description: Contact information.
            description:
                type: str
                description: System description.
            engine_id:
                aliases: ['engine-id']
                type: str
                description: Local SNMP engineID string
            location:
                type: str
                description: System location.
            status:
                type: str
                description:
                    - Enable/disable SNMP.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            trap_cpu_high_exclude_nice_threshold:
                aliases: ['trap-cpu-high-exclude-nice-threshold']
                type: int
                description: SNMP trap for CPU usage threshold
            trap_high_cpu_threshold:
                aliases: ['trap-high-cpu-threshold']
                type: int
                description: SNMP trap for CPU usage threshold.
            trap_low_memory_threshold:
                aliases: ['trap-low-memory-threshold']
                type: int
                description: SNMP trap for memory usage threshold.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SNMP configuration.
      fortinet.fortimanager.fmgr_system_snmp_sysinfo:
        # workspace_locking_adom: <global or your adom name>
        system_snmp_sysinfo:
          # contact_info: <string>
          # description: <string>
          # engine_id: <string>
          # location: <string>
          # status: <value in [disable, enable]>
          # trap_cpu_high_exclude_nice_threshold: <integer>
          # trap_high_cpu_threshold: <integer>
          # trap_low_memory_threshold: <integer>
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
        '/cli/global/system/snmp/sysinfo'
    ]
    module_arg_spec = {
        'system_snmp_sysinfo': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'contact_info': {'type': 'str'},
                'description': {'type': 'str'},
                'engine-id': {'type': 'str'},
                'location': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-cpu-high-exclude-nice-threshold': {'type': 'int'},
                'trap-high-cpu-threshold': {'type': 'int'},
                'trap-low-memory-threshold': {'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_snmp_sysinfo'),
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
