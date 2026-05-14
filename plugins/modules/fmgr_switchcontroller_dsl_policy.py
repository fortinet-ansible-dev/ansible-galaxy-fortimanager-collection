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
module: fmgr_switchcontroller_dsl_policy
short_description: DSL policy.
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
    switchcontroller_dsl_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            append_padding:
                type: str
                description: Device pause frame configuration.
                choices: ['disable', 'enable']
            cpe_aele:
                aliases: ['cpe-aele']
                type: str
                description: Cpe AELE.
                choices: ['disable', 'enable']
            cpe_aele_mode:
                aliases: ['cpe-aele-mode']
                type: str
                description: Cpe AELE-Mode with given string.
                choices: ['ELE_M0', 'ELE_DS', 'ELE_PB', 'ELE_MIN']
            cs:
                type: list
                elements: str
                description: CPE carrier set.
                choices: ['A43', 'B43', 'A43C', 'V43']
            ds_bitswap:
                aliases: ['ds-bitswap']
                type: str
                description: Enable/disable bitswap.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Policy name.
                required: true
            pause_frame:
                aliases: ['pause-frame']
                type: str
                description: Device pause frame configuration.
                choices: ['disable', 'enable']
            profile:
                type: str
                description: Vdsl CPE profile.
                choices: ['auto-30a', 'auto-17a', 'auto-12ab']
            type:
                type: str
                description: Type.
                choices: ['Procend', 'Proscend']
            us_bitswap:
                aliases: ['us-bitswap']
                type: str
                description: Enable/disable bitswap.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DSL policy.
      fortinet.fortimanager.fmgr_switchcontroller_dsl_policy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_dsl_policy:
          name: "your value" # Required variable, string
          # append_padding: <value in [disable, enable]>
          # cpe_aele: <value in [disable, enable]>
          # cpe_aele_mode: <value in [ELE_M0, ELE_DS, ELE_PB, ...]>
          # cs: ["A43", "B43", "A43C", "V43"]
          # ds_bitswap: <value in [disable, enable]>
          # pause_frame: <value in [disable, enable]>
          # profile: <value in [auto-30a, auto-17a, auto-12ab]>
          # type: <value in [Procend, Proscend]>
          # us_bitswap: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy',
        '/pm/config/global/obj/switch-controller/dsl/policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_dsl_policy': {
            'type': 'dict', 'v_range': [['7.0.3', '']],
            'options': {
                'append_padding': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cpe-aele': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cpe-aele-mode': {'v_range': [['7.0.3', '']], 'choices': ['ELE_M0', 'ELE_DS', 'ELE_PB', 'ELE_MIN'], 'type': 'str'},
                'cs': {'v_range': [['7.0.3', '']], 'type': 'list', 'choices': ['A43', 'B43', 'A43C', 'V43'], 'elements': 'str'},
                'ds-bitswap': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.0.3', '']], 'required': True, 'type': 'str'},
                'pause-frame': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'profile': {'v_range': [['7.0.3', '']], 'choices': ['auto-30a', 'auto-17a', 'auto-12ab'], 'type': 'str'},
                'type': {'v_range': [['7.0.3', '']], 'choices': ['Procend', 'Proscend'], 'type': 'str'},
                'us-bitswap': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_dsl_policy'),
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
