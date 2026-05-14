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
module: fmgr_virtualpatch_profile
short_description: Configure virtual-patch profile.
version_added: "2.3.0"
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
    virtualpatch_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action
                choices: ['pass', 'block']
            comment:
                type: str
                description: Comment.
            exemption:
                type: list
                elements: dict
                description: Exemption.
                suboptions:
                    device:
                        type: list
                        elements: str
                        description: Device MAC addresses.
                    id:
                        type: int
                        description: IDs.
                    rule:
                        type: list
                        elements: int
                        description: Patch signature rule IDs.
                    status:
                        type: str
                        description: Enable/disable exemption.
                        choices: ['disable', 'enable']
            log:
                type: str
                description: Enable/disable logging of detection.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Profile name.
                required: true
            severity:
                type: list
                elements: str
                description: Relative severity of the signature
                choices: ['low', 'medium', 'high', 'critical', 'info']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure virtual-patch profile.
      fortinet.fortimanager.fmgr_virtualpatch_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        virtualpatch_profile:
          name: "your value" # Required variable, string
          # action: <value in [pass, block]>
          # comment: <string>
          # exemption:
          #   - device: <list or string>
          #     id: <integer>
          #     rule: <list or integer>
          #     status: <value in [disable, enable]>
          # log: <value in [disable, enable]>
          # severity: ["low", "medium", "high", "critical", "info"]
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
        '/pm/config/adom/{adom}/obj/virtual-patch/profile',
        '/pm/config/global/obj/virtual-patch/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'virtualpatch_profile': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'action': {'v_range': [['7.4.1', '']], 'choices': ['pass', 'block'], 'type': 'str'},
                'comment': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'exemption': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'device': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'rule': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'int'},
                        'status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'log': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'severity': {'v_range': [['7.4.1', '']], 'type': 'list', 'choices': ['low', 'medium', 'high', 'critical', 'info'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'virtualpatch_profile'),
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
