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
module: fmgr_firewall_casbprofile_saasapplication
short_description: Firewall casb profile saas application
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
    firewall_casbprofile_saasapplication:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_rule:
                aliases: ['access-rule']
                type: list
                elements: dict
                description: Access rule.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices: ['block', 'monitor', 'bypass']
                    bypass:
                        type: list
                        elements: str
                        description: Bypass.
                        choices: ['av', 'dlp', 'web-filter', 'file-filter', 'video-filter']
                    name:
                        type: str
                        description: Name.
            custom_control:
                aliases: ['custom-control']
                type: list
                elements: dict
                description: Custom control.
                suboptions:
                    name:
                        type: str
                        description: Name.
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
            domain_control:
                aliases: ['domain-control']
                type: str
                description: Domain control.
                choices: ['disable', 'enable']
            domain_control_domains:
                aliases: ['domain-control-domains']
                type: list
                elements: str
                description: Domain control domains.
            log:
                type: str
                description: Log.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Name.
                required: true
            safe_search:
                aliases: ['safe-search']
                type: str
                description: Safe search.
                choices: ['disable', 'enable']
            safe_search_control:
                aliases: ['safe-search-control']
                type: list
                elements: str
                description: Safe search control.
            tenant_control:
                aliases: ['tenant-control']
                type: str
                description: Tenant control.
                choices: ['disable', 'enable']
            tenant_control_tenants:
                aliases: ['tenant-control-tenants']
                type: list
                elements: str
                description: Tenant control tenants.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Firewall casb profile saas application
      fortinet.fortimanager.fmgr_firewall_casbprofile_saasapplication:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        casb_profile: <your own value>
        state: present # <value in [present, absent]>
        firewall_casbprofile_saasapplication:
          name: "your value" # Required variable, string
          # access_rule:
          #   - action: <value in [block, monitor, bypass]>
          #     bypass: ["av", "dlp", "web-filter", "file-filter", "video-filter"]
          #     name: <string>
          # custom_control:
          #   - name: <string>
          #     option:
          #       - name: <string>
          #         user_input: <list or string>
          # domain_control: <value in [disable, enable]>
          # domain_control_domains: <list or string>
          # log: <value in [disable, enable]>
          # safe_search: <value in [disable, enable]>
          # safe_search_control: <list or string>
          # tenant_control: <value in [disable, enable]>
          # tenant_control_tenants: <list or string>
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
        '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application',
        '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'casb-profile': {'type': 'str', 'api_name': 'casb_profile'},
        'casb_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_casbprofile_saasapplication': {
            'type': 'dict', 'v_range': [['7.4.1', '7.4.1']],
            'options': {
                'access-rule': {
                    'v_range': [['7.4.1', '7.4.1']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.1', '7.4.1']], 'choices': ['block', 'monitor', 'bypass'], 'type': 'str'},
                        'bypass': {
                            'v_range': [['7.4.1', '7.4.1']],
                            'type': 'list',
                            'choices': ['av', 'dlp', 'web-filter', 'file-filter', 'video-filter'],
                            'elements': 'str'
                        },
                        'name': {'v_range': [['7.4.1', '7.4.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'custom-control': {
                    'v_range': [['7.4.1', '7.4.1']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.1', '7.4.1']], 'type': 'str'},
                        'option': {
                            'v_range': [['7.4.1', '7.4.1']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.1', '7.4.1']], 'type': 'str'},
                                'user-input': {'v_range': [['7.4.1', '7.4.1']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'domain-control': {'v_range': [['7.4.1', '7.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'domain-control-domains': {'v_range': [['7.4.1', '7.4.1']], 'type': 'list', 'elements': 'str'},
                'log': {'v_range': [['7.4.1', '7.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.1', '7.4.1']], 'required': True, 'type': 'str'},
                'safe-search': {'v_range': [['7.4.1', '7.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'safe-search-control': {'v_range': [['7.4.1', '7.4.1']], 'type': 'list', 'elements': 'str'},
                'tenant-control': {'v_range': [['7.4.1', '7.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tenant-control-tenants': {'v_range': [['7.4.1', '7.4.1']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_casbprofile_saasapplication'),
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
