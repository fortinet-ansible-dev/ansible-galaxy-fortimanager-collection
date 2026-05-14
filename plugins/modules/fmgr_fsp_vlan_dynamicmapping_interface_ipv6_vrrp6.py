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
module: fmgr_fsp_vlan_dynamicmapping_interface_ipv6_vrrp6
short_description: IPv6 VRRP configuration.
version_added: "2.1.0"
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    fsp_vlan_dynamicmapping_interface_ipv6_vrrp6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accept_mode:
                aliases: ['accept-mode']
                type: str
                description: Accept mode.
                choices: ['disable', 'enable']
            adv_interval:
                aliases: ['adv-interval']
                type: int
                description: Adv interval.
            preempt:
                type: str
                description: Preempt.
                choices: ['disable', 'enable']
            priority:
                type: int
                description: Priority.
            start_time:
                aliases: ['start-time']
                type: int
                description: Start time.
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            vrdst6:
                type: str
                description: Vrdst6.
            vrgrp:
                type: int
                description: Vrgrp.
            vrid:
                type: int
                description: Vrid.
            vrip6:
                type: str
                description: Vrip6.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 VRRP configuration.
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_ipv6_vrrp6:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vlan: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dynamicmapping_interface_ipv6_vrrp6:
          # accept_mode: <value in [disable, enable]>
          # adv_interval: <integer>
          # preempt: <value in [disable, enable]>
          # priority: <integer>
          # start_time: <integer>
          # status: <value in [disable, enable]>
          # vrdst6: <string>
          # vrgrp: <integer>
          # vrid: <integer>
          # vrip6: <string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6': {
            'type': 'dict', 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'accept-mode': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'adv-interval': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'preempt': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'start-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'status': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrdst6': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'vrgrp': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'vrid': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'vrip6': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6'),
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
