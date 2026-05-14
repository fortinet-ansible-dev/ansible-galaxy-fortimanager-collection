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
module: fmgr_fmg_sasemanager_settings
short_description: Fmg sase manager settings
version_added: "2.7.0"
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
    fmg_sasemanager_settings:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address:
                type: list
                elements: str
                description: Address.
            profile_group:
                aliases: ['profile-group']
                type: list
                elements: str
                description: Profile group.
            sync_address:
                aliases: ['sync-address']
                type: str
                description: Sync address.
                choices: ['disable', 'specify', 'all']
            sync_profile_group:
                aliases: ['sync-profile-group']
                type: str
                description: Sync profile group.
                choices: ['disable', 'specify', 'all']
            sync_user:
                aliases: ['sync-user']
                type: str
                description: Sync user.
                choices: ['disable', 'specify', 'all']
            user:
                type: list
                elements: str
                description: User.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Fmg sase manager settings
      fortinet.fortimanager.fmgr_fmg_sasemanager_settings:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        fmg_sasemanager_settings:
          # address: <list or string>
          # profile_group: <list or string>
          # sync_address: <value in [disable, specify, all]>
          # sync_profile_group: <value in [disable, specify, all]>
          # sync_user: <value in [disable, specify, all]>
          # user: <list or string>
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
        '/pm/config/adom/{adom}/obj/fmg/sase-manager/settings',
        '/pm/config/global/obj/fmg/sase-manager/settings'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fmg_sasemanager_settings': {
            'type': 'dict', 'v_range': [['7.6.0', '7.6.1']],
            'options': {
                'address': {'v_range': [['7.6.0', '7.6.1']], 'type': 'list', 'elements': 'str'},
                'profile-group': {'v_range': [['7.6.0', '7.6.1']], 'type': 'list', 'elements': 'str'},
                'sync-address': {'v_range': [['7.6.0', '7.6.1']], 'choices': ['disable', 'specify', 'all'], 'type': 'str'},
                'sync-profile-group': {'v_range': [['7.6.0', '7.6.1']], 'choices': ['disable', 'specify', 'all'], 'type': 'str'},
                'sync-user': {'v_range': [['7.6.0', '7.6.1']], 'choices': ['disable', 'specify', 'all'], 'type': 'str'},
                'user': {'v_range': [['7.6.0', '7.6.1']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmg_sasemanager_settings'),
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
