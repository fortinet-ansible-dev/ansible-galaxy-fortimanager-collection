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
module: fmgr_apcfgprofile_commandlist
short_description: AP local configuration command list.
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
    apcfg-profile:
        description: Deprecated, please use "apcfg_profile"
        type: str
    apcfg_profile:
        description: The parameter (apcfg-profile) in requested url.
        type: str
    apcfgprofile_commandlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Command ID.
                required: true
            name:
                type: str
                description: AP local configuration command name.
            passwd_value:
                aliases: ['passwd-value']
                type: raw
                description: (list) AP local configuration command password value.
            type:
                type: str
                description: The command type
                choices: ['non-password', 'password']
            value:
                type: str
                description: AP local configuration command value.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: AP local configuration command list.
      fortinet.fortimanager.fmgr_apcfgprofile_commandlist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        apcfg_profile: <your own value>
        state: present # <value in [present, absent]>
        apcfgprofile_commandlist:
          id: 0 # Required variable, integer
          # name: <string>
          # passwd_value: <list or string>
          # type: <value in [non-password, password]>
          # value: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list',
        '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'apcfg-profile': {'type': 'str', 'api_name': 'apcfg_profile'},
        'apcfg_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'apcfgprofile_commandlist': {
            'type': 'dict', 'v_range': [['6.4.6', '']],
            'options': {
                'id': {'v_range': [['6.4.6', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['6.4.6', '']], 'type': 'str'},
                'passwd-value': {'v_range': [['6.4.6', '']], 'no_log': True, 'type': 'raw'},
                'type': {'v_range': [['6.4.6', '']], 'choices': ['non-password', 'password'], 'type': 'str'},
                'value': {'v_range': [['6.4.6', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'apcfgprofile_commandlist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
