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
module: fmgr_switchcontroller_fortilinksettings
short_description: Configure integrated FortiLink settings for FortiSwitch.
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
    switchcontroller_fortilinksettings:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fortilink:
                type: str
                description: FortiLink interface to which this fortilink-setting belongs.
            inactive_timer:
                aliases: ['inactive-timer']
                type: int
                description: Time interval
            link_down_flush:
                aliases: ['link-down-flush']
                type: str
                description: Clear NAC and dynamic devices on switch ports on link down event.
                choices: ['disable', 'enable']
            nac_ports:
                aliases: ['nac-ports']
                type: dict
                description: Nac ports.
                suboptions:
                    lan_segment:
                        aliases: ['lan-segment']
                        type: str
                        description: Enable/disable LAN segment feature on the FortiLink interface.
                        choices: ['disabled', 'enabled']
                    member_change:
                        aliases: ['member-change']
                        type: int
                        description: Member change.
                    nac_lan_interface:
                        aliases: ['nac-lan-interface']
                        type: str
                        description: Configure NAC LAN interface.
                    nac_segment_vlans:
                        aliases: ['nac-segment-vlans']
                        type: raw
                        description: (list) Configure NAC segment VLANs.
                    onboarding_vlan:
                        aliases: ['onboarding-vlan']
                        type: str
                        description: Default NAC Onboarding VLAN when NAC devices are discovered.
                    parent_key:
                        aliases: ['parent-key']
                        type: str
                        description: Parent key.
                    bounce_nac_port:
                        aliases: ['bounce-nac-port']
                        type: str
                        description: Enable/disable bouncing
                        choices: ['disable', 'enable']
            name:
                type: str
                description: FortiLink settings name.
                required: true
            access_vlan_mode:
                aliases: ['access-vlan-mode']
                type: str
                description: Intra VLAN traffic behavior with loss of connection to the FortiGate.
                choices: ['legacy', 'fail-open', 'fail-close']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure integrated FortiLink settings for FortiSwitch.
      fortinet.fortimanager.fmgr_switchcontroller_fortilinksettings:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_fortilinksettings:
          name: "your value" # Required variable, string
          # fortilink: <string>
          # inactive_timer: <integer>
          # link_down_flush: <value in [disable, enable]>
          # nac_ports:
          #   lan_segment: <value in [disabled, enabled]>
          #   member_change: <integer>
          #   nac_lan_interface: <string>
          #   nac_segment_vlans: <list or string>
          #   onboarding_vlan: <string>
          #   parent_key: <string>
          #   bounce_nac_port: <value in [disable, enable]>
          # access_vlan_mode: <value in [legacy, fail-open, fail-close]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings',
        '/pm/config/global/obj/switch-controller/fortilink-settings'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_fortilinksettings': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'fortilink': {'v_range': [['7.2.1', '7.2.3'], ['7.2.6', '7.4.0'], ['7.4.3', '']], 'type': 'str'},
                'inactive-timer': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'link-down-flush': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nac-ports': {
                    'v_range': [['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'lan-segment': {'v_range': [['7.2.1', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'member-change': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'nac-lan-interface': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'nac-segment-vlans': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'onboarding-vlan': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'parent-key': {'v_range': [['7.2.1', '']], 'no_log': True, 'type': 'str'},
                        'bounce-nac-port': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'access-vlan-mode': {'v_range': [['7.4.1', '']], 'choices': ['legacy', 'fail-open', 'fail-close'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_fortilinksettings'),
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
