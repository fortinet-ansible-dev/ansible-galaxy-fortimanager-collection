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
module: fmgr_switchcontroller_vlanpolicy
short_description: Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
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
    switchcontroller_vlanpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowed_vlans:
                aliases: ['allowed-vlans']
                type: raw
                description: (list) Allowed VLANs to be applied when using this VLAN policy.
            allowed_vlans_all:
                aliases: ['allowed-vlans-all']
                type: str
                description: Enable/disable all defined VLANs when using this VLAN policy.
                choices: ['disable', 'enable']
            description:
                type: str
                description: Description for the VLAN policy.
            discard_mode:
                aliases: ['discard-mode']
                type: str
                description: Discard mode to be applied when using this VLAN policy.
                choices: ['none', 'all-untagged', 'all-tagged']
            name:
                type: str
                description: VLAN policy name.
                required: true
            untagged_vlans:
                aliases: ['untagged-vlans']
                type: raw
                description: (list) Untagged VLANs to be applied when using this VLAN policy.
            vlan:
                type: str
                description: Native VLAN to be applied when using this VLAN policy.
            fortilink:
                type: raw
                description: (list) FortiLink interface for which this VLAN policy belongs to.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
      fortinet.fortimanager.fmgr_switchcontroller_vlanpolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_vlanpolicy:
          name: "your value" # Required variable, string
          # allowed_vlans: <list or string>
          # allowed_vlans_all: <value in [disable, enable]>
          # description: <string>
          # discard_mode: <value in [none, all-untagged, all-tagged]>
          # untagged_vlans: <list or string>
          # vlan: <string>
          # fortilink: <list or string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/vlan-policy',
        '/pm/config/global/obj/switch-controller/vlan-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_vlanpolicy': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'allowed-vlans': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'allowed-vlans-all': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'description': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'discard-mode': {'v_range': [['7.2.1', '']], 'choices': ['none', 'all-untagged', 'all-tagged'], 'type': 'str'},
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'untagged-vlans': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'vlan': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'fortilink': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_vlanpolicy'),
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
