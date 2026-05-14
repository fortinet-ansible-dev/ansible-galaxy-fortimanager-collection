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
module: fmgr_casb_profile_saasapplication_accessrule
short_description: CASB profile access rule.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    saas-application:
        description: Deprecated, please use "saas_application"
        type: str
    saas_application:
        description: The parameter (saas-application) in requested url.
        type: str
    casb_profile_saasapplication_accessrule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: CASB access rule action.
                choices: ['block', 'bypass', 'monitor']
            bypass:
                type: list
                elements: str
                description: CASB bypass options.
                choices: ['av', 'dlp', 'web-filter', 'file-filter', 'video-filter']
            name:
                type: str
                description: CASB access rule activity name.
                required: true
            attribute_filter:
                aliases: ['attribute-filter']
                type: list
                elements: dict
                description: Attribute filter.
                suboptions:
                    action:
                        type: str
                        description: CASB access rule tenant control action.
                        choices: ['block', 'monitor', 'bypass']
                    attribute_match:
                        aliases: ['attribute-match']
                        type: list
                        elements: str
                        description: CASB access rule tenant match.
                    id:
                        type: int
                        description: CASB tenant control ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CASB profile access rule.
      fortinet.fortimanager.fmgr_casb_profile_saasapplication_accessrule:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        saas_application: <your own value>
        state: present # <value in [present, absent]>
        casb_profile_saasapplication_accessrule:
          name: "your value" # Required variable, string
          # action: <value in [block, bypass, monitor]>
          # bypass: ["av", "dlp", "web-filter", "file-filter", "video-filter"]
          # attribute_filter:
          #   - action: <value in [block, monitor, bypass]>
          #     attribute_match: <list or string>
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
        '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule',
        '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'saas-application': {'type': 'str', 'api_name': 'saas_application'},
        'saas_application': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_profile_saasapplication_accessrule': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'action': {'v_range': [['7.4.1', '']], 'choices': ['block', 'bypass', 'monitor'], 'type': 'str'},
                'bypass': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'choices': ['av', 'dlp', 'web-filter', 'file-filter', 'video-filter'],
                    'elements': 'str'
                },
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'attribute-filter': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'monitor', 'bypass'], 'type': 'str'},
                        'attribute-match': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_profile_saasapplication_accessrule'),
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
