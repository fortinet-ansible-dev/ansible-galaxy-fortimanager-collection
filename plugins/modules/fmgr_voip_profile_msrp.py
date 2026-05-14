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
module: fmgr_voip_profile_msrp
short_description: MSRP.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    voip_profile_msrp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            log_violations:
                aliases: ['log-violations']
                type: str
                description: Enable/disable logging of MSRP violations.
                choices: ['disable', 'enable']
            max_msg_size:
                aliases: ['max-msg-size']
                type: int
                description: Maximum allowable MSRP message size
            max_msg_size_action:
                aliases: ['max-msg-size-action']
                type: str
                description: Action for violation of max-msg-size.
                choices: ['pass', 'block', 'reset', 'monitor']
            status:
                type: str
                description: Enable/disable MSRP.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: MSRP.
      fortinet.fortimanager.fmgr_voip_profile_msrp:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        voip_profile_msrp:
          # log_violations: <value in [disable, enable]>
          # max_msg_size: <integer>
          # max_msg_size_action: <value in [pass, block, reset, ...]>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/voip/profile/{profile}/msrp',
        '/pm/config/global/obj/voip/profile/{profile}/msrp'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'voip_profile_msrp': {
            'type': 'dict', 'v_range': [['7.0.2', '']],
            'options': {
                'log-violations': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-msg-size': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'max-msg-size-action': {'v_range': [['7.0.2', '']], 'choices': ['pass', 'block', 'reset', 'monitor'], 'type': 'str'},
                'status': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'voip_profile_msrp'),
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
