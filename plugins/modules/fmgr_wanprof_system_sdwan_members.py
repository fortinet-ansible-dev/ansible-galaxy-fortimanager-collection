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
module: fmgr_wanprof_system_sdwan_members
short_description: FortiGate interfaces added to the SD-WAN.
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
    wanprof_system_sdwan_members:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _dynamic_member:
                aliases: ['_dynamic-member']
                type: str
                description: Dynamic member.
            comment:
                type: str
                description: Comments.
            cost:
                type: int
                description: Cost of this interface for services in SLA mode
            gateway:
                type: str
                description: The default gateway for this interface.
            gateway6:
                type: str
                description: IPv6 gateway.
            ingress_spillover_threshold:
                aliases: ['ingress-spillover-threshold']
                type: int
                description: Ingress spillover threshold for this interface
            interface:
                type: str
                description: Interface name.
            priority:
                type: int
                description: Priority of the interface
            seq_num:
                aliases: ['seq-num']
                type: int
                description: Sequence number
                required: true
            source:
                type: str
                description: Source IP address used in the health-check packet to the server.
            source6:
                type: str
                description: Source IPv6 address used in the health-check packet to the server.
            spillover_threshold:
                aliases: ['spillover-threshold']
                type: int
                description: Egress spillover threshold for this interface
            status:
                type: str
                description: Enable/disable this interface in the SD-WAN.
                choices: ['disable', 'enable']
            volume_ratio:
                aliases: ['volume-ratio']
                type: int
                description: Measured volume ratio
            weight:
                type: int
                description: Weight of this interface for weighted load balancing.
            zone:
                type: str
                description: Zone name.
            priority6:
                type: int
                description: Priority of the interface for IPv6
            preferred_source:
                aliases: ['preferred-source']
                type: str
                description: Preferred source of route for this member.
            transport_group:
                aliases: ['transport-group']
                type: int
                description: Measured transport group
            priority_in_sla:
                aliases: ['priority-in-sla']
                type: int
                description: Preferred priority of routes to this member when this member is in-sla
            priority_out_sla:
                aliases: ['priority-out-sla']
                type: int
                description: Preferred priority of routes to this member when this member is out-of-sla
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGate interfaces added to the SD-WAN.
      fortinet.fortimanager.fmgr_wanprof_system_sdwan_members:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        wanprof: <your own value>
        state: present # <value in [present, absent]>
        wanprof_system_sdwan_members:
          seq_num: 0 # Required variable, integer
          # _dynamic_member: <string>
          # comment: <string>
          # cost: <integer>
          # gateway: <string>
          # gateway6: <string>
          # ingress_spillover_threshold: <integer>
          # interface: <string>
          # priority: <integer>
          # source: <string>
          # source6: <string>
          # spillover_threshold: <integer>
          # status: <value in [disable, enable]>
          # volume_ratio: <integer>
          # weight: <integer>
          # zone: <string>
          # priority6: <integer>
          # preferred_source: <string>
          # transport_group: <integer>
          # priority_in_sla: <integer>
          # priority_out_sla: <integer>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'wanprof_system_sdwan_members': {
            'type': 'dict', 'v_range': [['6.4.1', '']],
            'options': {
                '_dynamic-member': {'v_range': [['6.4.1', '6.4.15']], 'type': 'str'},
                'comment': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'cost': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'gateway': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'gateway6': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'ingress-spillover-threshold': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'interface': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'priority': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'seq-num': {'v_range': [['6.4.1', '']], 'required': True, 'type': 'int'},
                'source': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'source6': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'spillover-threshold': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'status': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'volume-ratio': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'weight': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'zone': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'priority6': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'preferred-source': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'transport-group': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'priority-in-sla': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'priority-out-sla': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan_members'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'seq-num', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
