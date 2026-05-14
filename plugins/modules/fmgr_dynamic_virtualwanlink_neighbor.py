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
module: fmgr_dynamic_virtualwanlink_neighbor
short_description: Dynamic virtual wan link neighbor
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
    dynamic_virtualwanlink_neighbor:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    description:
                        type: str
                        description: Description.
                    ip:
                        type: str
                        description: Ip.
                    role:
                        type: str
                        description: Role.
                        choices: ['primary', 'secondary', 'standalone']
            ip:
                type: str
                description: Ip.
            name:
                type: str
                description: Name.
                required: true
            role:
                type: str
                description: Role.
                choices: ['primary', 'secondary', 'standalone']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Dynamic virtual wan link neighbor
      fortinet.fortimanager.fmgr_dynamic_virtualwanlink_neighbor:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dynamic_virtualwanlink_neighbor:
          name: "your value" # Required variable, string
          # description: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     description: <string>
          #     ip: <string>
          #     role: <value in [primary, secondary, standalone]>
          # ip: <string>
          # role: <value in [primary, secondary, standalone]>
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
        '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor',
        '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dynamic_virtualwanlink_neighbor': {
            'type': 'dict', 'v_range': [['6.2.2', '6.4.15']],
            'options': {
                'description': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['6.2.2', '6.4.15']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['6.2.2', '6.4.15']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'},
                                'vdom': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'description': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'},
                        'ip': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'},
                        'role': {'v_range': [['6.2.2', '6.4.15']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ip': {'v_range': [['6.2.2', '6.4.15']], 'type': 'str'},
                'name': {'v_range': [['6.2.2', '6.4.15']], 'required': True, 'type': 'str'},
                'role': {'v_range': [['6.2.2', '6.4.15']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dynamic_virtualwanlink_neighbor'),
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
