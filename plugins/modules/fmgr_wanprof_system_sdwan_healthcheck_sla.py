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
module: fmgr_wanprof_system_sdwan_healthcheck_sla
short_description: Service level agreement
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
    health-check:
        description: Deprecated, please use "health_check"
        type: str
    health_check:
        description: The parameter (health-check) in requested url.
        type: str
    wanprof_system_sdwan_healthcheck_sla:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: SLA ID.
                required: true
            jitter_threshold:
                aliases: ['jitter-threshold']
                type: int
                description: Jitter for SLA to make decision in milliseconds.
            latency_threshold:
                aliases: ['latency-threshold']
                type: int
                description: Latency for SLA to make decision in milliseconds.
            link_cost_factor:
                aliases: ['link-cost-factor']
                type: list
                elements: str
                description: Criteria on which to base link selection.
                choices: ['latency', 'jitter', 'packet-loss', 'mos', 'remote', 'custom-profile-1']
            packetloss_threshold:
                aliases: ['packetloss-threshold']
                type: int
                description: Packet loss for SLA to make decision in percentage.
            mos_threshold:
                aliases: ['mos-threshold']
                type: str
                description: Minimum Mean Opinion Score for SLA to be marked as pass.
            priority_in_sla:
                aliases: ['priority-in-sla']
                type: int
                description: Value to be distributed into routing table when in-sla
            priority_out_sla:
                aliases: ['priority-out-sla']
                type: int
                description: Value to be distributed into routing table when out-sla
            custom_profile_threshold:
                aliases: ['custom-profile-threshold']
                type: int
                description: Custom profile threshold for SLA to be marked as pass
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Service level agreement
      fortinet.fortimanager.fmgr_wanprof_system_sdwan_healthcheck_sla:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        wanprof: <your own value>
        health_check: <your own value>
        state: present # <value in [present, absent]>
        wanprof_system_sdwan_healthcheck_sla:
          id: 0 # Required variable, integer
          # jitter_threshold: <integer>
          # latency_threshold: <integer>
          # link_cost_factor: ["latency", "jitter", "packet-loss", "mos", "remote",
          #                    "custom-profile-1"]
          # packetloss_threshold: <integer>
          # mos_threshold: <string>
          # priority_in_sla: <integer>
          # priority_out_sla: <integer>
          # custom_profile_threshold: <integer>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'health-check': {'type': 'str', 'api_name': 'health_check'},
        'health_check': {'type': 'str'},
        'wanprof_system_sdwan_healthcheck_sla': {
            'type': 'dict', 'v_range': [['6.4.1', '']],
            'options': {
                'id': {'v_range': [['6.4.1', '']], 'required': True, 'type': 'int'},
                'jitter-threshold': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'latency-threshold': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'link-cost-factor': {
                    'v_range': [['6.4.1', '']],
                    'type': 'list',
                    'choices': ['latency', 'jitter', 'packet-loss', 'mos', 'remote', 'custom-profile-1'],
                    'elements': 'str'
                },
                'packetloss-threshold': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'mos-threshold': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'priority-in-sla': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'priority-out-sla': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'custom-profile-threshold': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan_healthcheck_sla'),
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
