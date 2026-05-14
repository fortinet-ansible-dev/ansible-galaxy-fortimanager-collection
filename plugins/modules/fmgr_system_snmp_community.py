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
module: fmgr_system_snmp_community
short_description: SNMP community configuration.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_snmp_community:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            events:
                type: list
                elements: str
                description:
                    - SNMP trap events.
                    - disk_low - Disk usage too high.
                    - ha_switch - HA switch.
                    - intf_ip_chg - Interface IP address changed.
                    - sys_reboot - System reboot.
                    - cpu_high - CPU usage too high.
                    - mem_low - Available memory is low.
                    - log-alert - Log base alert message.
                    - log-rate - High incoming log rate detected.
                    - log-data-rate - High incoming log data rate detected.
                    - lic-gbday - High licensed log GB/day detected.
                    - lic-dev-quota - High licensed device quota detected.
                    - cpu-high-exclude-nice - CPU usage exclude NICE threshold.
                choices: ['disk_low', 'ha_switch', 'intf_ip_chg', 'sys_reboot', 'cpu_high',
                          'mem_low', 'log-alert', 'log-rate', 'log-data-rate', 'lic-gbday',
                          'lic-dev-quota', 'cpu-high-exclude-nice']
            hosts:
                type: list
                elements: dict
                description: Hosts.
                suboptions:
                    id:
                        type: int
                        description: Host entry ID.
                    interface:
                        type: str
                        description: Allow interface name.
                    ip:
                        type: str
                        description: Allow host IP address.
            hosts6:
                type: list
                elements: dict
                description: Hosts6.
                suboptions:
                    id:
                        type: int
                        description: Host entry ID.
                    interface:
                        type: str
                        description: Allow interface name.
                    ip:
                        type: str
                        description: Allow host IP address.
            id:
                type: int
                description: Community ID.
                required: true
            name:
                type: str
                description: Community name.
            query_v1_port:
                type: int
                description: SNMP v1 query port.
            query_v1_status:
                type: str
                description:
                    - Enable/disable SNMP v1 query.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_v2c_port:
                type: int
                description: SNMP v2c query port.
            query_v2c_status:
                type: str
                description:
                    - Enable/disable SNMP v2c query.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            status:
                type: str
                description:
                    - Enable/disable community.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            trap_v1_rport:
                type: int
                description: SNMP v1 trap remote port.
            trap_v1_status:
                type: str
                description:
                    - Enable/disable SNMP v1 trap.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            trap_v2c_rport:
                type: int
                description: SNMP v2c trap remote port.
            trap_v2c_status:
                type: str
                description:
                    - Enable/disable SNMP v2c trap.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
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
    - name: SNMP community configuration.
      fortinet.fortimanager.fmgr_system_snmp_community:
        bypass_validation: false
        state: present
        system_snmp_community:
          id: 1
          name: ansible-test-snmp
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the SNMP communities
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_snmp_community"
          params:
            community: "your_value"
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
        '/cli/global/system/snmp/community'
    ]
    module_arg_spec = {
        'system_snmp_community': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'events': {
                    'type': 'list',
                    'choices': [
                        'disk_low', 'ha_switch', 'intf_ip_chg', 'sys_reboot', 'cpu_high', 'mem_low', 'log-alert', 'log-rate', 'log-data-rate',
                        'lic-gbday', 'lic-dev-quota', 'cpu-high-exclude-nice'
                    ],
                    'elements': 'str'
                },
                'hosts': {'type': 'list', 'options': {'id': {'type': 'int'}, 'interface': {'type': 'str'}, 'ip': {'type': 'str'}}, 'elements': 'dict'},
                'hosts6': {'type': 'list', 'options': {'id': {'type': 'int'}, 'interface': {'type': 'str'}, 'ip': {'type': 'str'}}, 'elements': 'dict'},
                'id': {'required': True, 'type': 'int'},
                'name': {'type': 'str'},
                'query_v1_port': {'type': 'int'},
                'query_v1_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query_v2c_port': {'type': 'int'},
                'query_v2c_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'trap_v1_rport': {'type': 'int'},
                'trap_v1_status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'trap_v2c_rport': {'type': 'int'},
                'trap_v2c_status': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_snmp_community'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
