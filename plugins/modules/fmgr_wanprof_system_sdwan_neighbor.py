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
module: fmgr_wanprof_system_sdwan_neighbor
short_description: Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    wanprof:
        description: The parameter (wanprof) in requested url.
        type: str
        required: true
    wanprof_system_sdwan_neighbor:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            health_check:
                aliases: ['health-check']
                type: str
                description: SD-WAN health-check name.
            ip:
                type: str
                description: IP/IPv6 address of neighbor.
            member:
                type: raw
                description: (list or str) Member sequence number.
            role:
                type: str
                description: Role of neighbor.
                choices: ['primary', 'secondary', 'standalone']
            sla_id:
                aliases: ['sla-id']
                type: int
                description: SLA ID.
            minimum_sla_meet_members:
                aliases: ['minimum-sla-meet-members']
                type: int
                description: Minimum number of members which meet SLA when the neighbor is preferred.
            mode:
                type: str
                description: What metric to select the neighbor.
                choices: ['sla', 'speedtest']
            service_id:
                aliases: ['service-id']
                type: str
                description: SD-WAN service ID to work with the neighbor.
            route_metric:
                aliases: ['route-metric']
                type: str
                description: Route-metric of neighbor.
                choices: ['preferable', 'priority']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
      fortinet.fortimanager.fmgr_wanprof_system_sdwan_neighbor:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        wanprof: <your own value>
        state: present # <value in [present, absent]>
        wanprof_system_sdwan_neighbor:
          # health_check: <string>
          # ip: <string>
          # member: <list or string>
          # role: <value in [primary, secondary, standalone]>
          # sla_id: <integer>
          # minimum_sla_meet_members: <integer>
          # mode: <value in [sla, speedtest]>
          # service_id: <string>
          # route_metric: <value in [preferable, priority]>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'wanprof_system_sdwan_neighbor': {
            'type': 'dict', 'v_range': [['6.4.1', '']],
            'options': {
                'health-check': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'ip': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'member': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                'role': {'v_range': [['6.4.1', '']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                'sla-id': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'minimum-sla-meet-members': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'mode': {'v_range': [['7.0.1', '']], 'choices': ['sla', 'speedtest'], 'type': 'str'},
                'service-id': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'route-metric': {'v_range': [['7.6.2', '']], 'choices': ['preferable', 'priority'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan_neighbor'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
