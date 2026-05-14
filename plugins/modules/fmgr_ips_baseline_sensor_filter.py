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
module: fmgr_ips_baseline_sensor_filter
short_description: Ips baseline sensor filter
version_added: "2.2.0"
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
    sensor:
        description: The parameter (sensor) in requested url.
        type: str
        required: true
    ips_baseline_sensor_filter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action of selected rules.
                choices: ['pass', 'block', 'default', 'reset']
            application:
                type: raw
                description: (list) Vulnerable application filter.
            application_real:
                aliases: ['application(real)']
                type: str
                description: Application
            location:
                type: raw
                description: (list) Vulnerability location filter.
            location_real:
                aliases: ['location(real)']
                type: str
                description: Location
            log:
                type: str
                description: Enable/disable logging of selected rules.
                choices: ['disable', 'enable', 'default']
            log_packet:
                aliases: ['log-packet']
                type: str
                description: Enable/disable packet logging of selected rules.
                choices: ['disable', 'enable', 'default']
            name:
                type: str
                description: Filter name.
                required: true
            os:
                type: raw
                description: (list) Vulnerable OS filter.
            os_real:
                aliases: ['os(real)']
                type: str
                description: Os
            protocol:
                type: raw
                description: (list) Vulnerable protocol filter.
            protocol_real:
                aliases: ['protocol(real)']
                type: str
                description: Protocol
            quarantine:
                type: str
                description: Quarantine IP or interface.
                choices: ['none', 'attacker', 'both', 'interface']
            quarantine_expiry:
                aliases: ['quarantine-expiry']
                type: int
                description: Duration of quarantine in minute.
            quarantine_log:
                aliases: ['quarantine-log']
                type: str
                description: Enable/disable logging of selected quarantine.
                choices: ['disable', 'enable']
            severity:
                type: raw
                description: (list) Vulnerability severity filter.
            severity_real:
                aliases: ['severity(real)']
                type: str
                description: Severity
            status:
                type: str
                description: Selected rules status.
                choices: ['disable', 'enable', 'default']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Ips baseline sensor filter
      fortinet.fortimanager.fmgr_ips_baseline_sensor_filter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        sensor: <your own value>
        state: present # <value in [present, absent]>
        ips_baseline_sensor_filter:
          name: "your value" # Required variable, string
          # action: <value in [pass, block, default, ...]>
          # application: <list or string>
          # application_real: <string>
          # location: <list or string>
          # location_real: <string>
          # log: <value in [disable, enable, default]>
          # log_packet: <value in [disable, enable, default]>
          # os: <list or string>
          # os_real: <string>
          # protocol: <list or string>
          # protocol_real: <string>
          # quarantine: <value in [none, attacker, both, ...]>
          # quarantine_expiry: <integer>
          # quarantine_log: <value in [disable, enable]>
          # severity: <list or string>
          # severity_real: <string>
          # status: <value in [disable, enable, default]>
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
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/filter',
        '/pm/config/global/obj/ips/baseline/sensor/{sensor}/filter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sensor': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ips_baseline_sensor_filter': {
            'type': 'dict', 'v_range': [['7.0.1', '7.0.2']],
            'options': {
                'action': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['pass', 'block', 'default', 'reset'], 'type': 'str'},
                'application': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'application(real)': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'location': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'location(real)': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'log': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                'log-packet': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                'name': {'v_range': [['7.0.1', '7.0.2']], 'required': True, 'type': 'str'},
                'os': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'os(real)': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'protocol': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'protocol(real)': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'quarantine': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                'quarantine-expiry': {'v_range': [['7.0.1', '7.0.2']], 'type': 'int'},
                'quarantine-log': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'severity(real)': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'status': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_baseline_sensor_filter'),
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
