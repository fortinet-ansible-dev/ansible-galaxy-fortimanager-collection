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
module: fmgr_user_deviceaccesslist
short_description: Configure device access control lists.
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
    user_deviceaccesslist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            default_action:
                aliases: ['default-action']
                type: str
                description: Accept or deny unknown/unspecified devices.
                choices: ['deny', 'accept']
            device_list:
                aliases: ['device-list']
                type: list
                elements: dict
                description: Device list.
                suboptions:
                    action:
                        type: str
                        description: Allow or block device.
                        choices: ['deny', 'accept']
                    device:
                        type: str
                        description: Firewall device or device group.
                    id:
                        type: int
                        description: Entry ID.
            name:
                type: str
                description: Device access list name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure device access control lists.
      fortinet.fortimanager.fmgr_user_deviceaccesslist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_deviceaccesslist:
          name: "your value" # Required variable, string
          # default_action: <value in [deny, accept]>
          # device_list:
          #   - action: <value in [deny, accept]>
          #     device: <string>
          #     id: <integer>
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
        '/pm/config/adom/{adom}/obj/user/device-access-list',
        '/pm/config/global/obj/user/device-access-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_deviceaccesslist': {
            'type': 'dict', 'v_range': [['6.2.2', '7.2.1']],
            'options': {
                'default-action': {'v_range': [['6.2.2', '7.2.1']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'device-list': {
                    'v_range': [['6.2.2', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.2.2', '7.2.1']], 'choices': ['deny', 'accept'], 'type': 'str'},
                        'device': {'v_range': [['6.2.2', '7.2.1']], 'type': 'str'},
                        'id': {'v_range': [['6.2.2', '7.2.1']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['6.2.2', '7.2.1']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_deviceaccesslist'),
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
