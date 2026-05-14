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
module: fmgr_firewall_casbprofile_saasapplication_customcontrol
short_description: Firewall casb profile saas application custom control
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
    casb-profile:
        description: Deprecated, please use "casb_profile"
        type: str
    casb_profile:
        description: The parameter (casb-profile) in requested url.
        type: str
    saas-application:
        description: Deprecated, please use "saas_application"
        type: str
    saas_application:
        description: The parameter (saas-application) in requested url.
        type: str
    firewall_casbprofile_saasapplication_customcontrol:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: Name.
                required: true
            option:
                type: list
                elements: dict
                description: Option.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    user_input:
                        aliases: ['user-input']
                        type: list
                        elements: str
                        description: User input.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Firewall casb profile saas application custom control
      fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication_customcontrol:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        casb_profile: <your own value>
        saas_application: <your own value>
        state: present # <value in [present, absent]>
        firewall_casbprofile_saasapplication_customcontrol:
          name: "your value" # Required variable, string
          # option:
          #   - name: <string>
          #     user_input: <list or string>
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
        '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control',
        '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'casb-profile': {'type': 'str', 'api_name': 'casb_profile'},
        'casb_profile': {'type': 'str'},
        'saas-application': {'type': 'str', 'api_name': 'saas_application'},
        'saas_application': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_casbprofile_saasapplication_customcontrol': {
            'type': 'dict', 'v_range': [['7.4.1', '7.4.1']],
            'options': {
                'name': {'v_range': [['7.4.1', '7.4.1']], 'required': True, 'type': 'str'},
                'option': {
                    'v_range': [['7.4.1', '7.4.1']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.1', '7.4.1']], 'type': 'str'},
                        'user-input': {'v_range': [['7.4.1', '7.4.1']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_casbprofile_saasapplication_customcontrol'),
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
