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
module: fmgr_pm_pblock_obj
short_description: Policy block adom
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    pkg_path:
        description: The parameter (pkg_path) in requested url.
        type: str
        required: true
    pm_pblock_obj:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: Name.
                required: true
            oid:
                type: int
                description: Oid.
            package_settings:
                aliases: ['package settings']
                type: dict
                description: Package settings.
                suboptions:
                    central_nat:
                        aliases: ['central-nat']
                        type: str
                        description: Central nat.
                        choices: ['disable', 'enable']
                    consolidated_firewall_mode:
                        aliases: ['consolidated-firewall-mode']
                        type: str
                        description: Consolidated firewall mode.
                        choices: ['disable', 'enable']
                    fwpolicy_implicit_log:
                        aliases: ['fwpolicy-implicit-log']
                        type: str
                        description: Fwpolicy implicit log.
                        choices: ['disable', 'enable']
                    fwpolicy6_implicit_log:
                        aliases: ['fwpolicy6-implicit-log']
                        type: str
                        description: Fwpolicy6 implicit log.
                        choices: ['disable', 'enable']
                    inspection_mode:
                        aliases: ['inspection-mode']
                        type: str
                        description: Inspection mode.
                        choices: ['proxy', 'flow']
                    ngfw_mode:
                        aliases: ['ngfw-mode']
                        type: str
                        description: Ngfw mode.
                        choices: ['profile-based', 'policy-based']
                    policy_offload_level:
                        aliases: ['policy-offload-level']
                        type: str
                        description: Policy offload level.
                        choices: ['disable', 'default', 'dos-offload', 'full-offload']
                    ssl_ssh_profile:
                        aliases: ['ssl-ssh-profile']
                        type: str
                        description: Ssl ssh profile.
            type:
                type: str
                description: Type.
                choices: ['pblock']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Policy block adom
      fortinet.fortimanager.fmgr_pm_pblock_obj:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg_path: <your own value>
        state: present # <value in [present, absent]>
        pm_pblock_obj:
          name: "your value" # Required variable, string
          # oid: <integer>
          # package_settings:
          #   central_nat: <value in [disable, enable]>
          #   consolidated_firewall_mode: <value in [disable, enable]>
          #   fwpolicy_implicit_log: <value in [disable, enable]>
          #   fwpolicy6_implicit_log: <value in [disable, enable]>
          #   inspection_mode: <value in [proxy, flow]>
          #   ngfw_mode: <value in [profile-based, policy-based]>
          #   policy_offload_level: <value in [disable, default, dos-offload, ...]>
          #   ssl_ssh_profile: <string>
          # type: <value in [pblock]>
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
        '/pm/pblock/adom/{adom}/{pkg_path}'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg_path': {'required': True, 'type': 'str'},
        'pm_pblock_obj': {
            'type': 'dict', 'v_range': [['7.0.3', '']],
            'options': {
                'name': {'v_range': [['7.0.3', '']], 'required': True, 'type': 'str'},
                'oid': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'package settings': {
                    'v_range': [['7.0.3', '']],
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy-implicit-log': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['7.0.3', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['7.0.3', '']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'policy-offload-level': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['disable', 'default', 'dos-offload', 'full-offload'],
                            'type': 'str'
                        },
                        'ssl-ssh-profile': {'v_range': [['7.0.3', '']], 'type': 'str'}
                    }
                },
                'type': {'v_range': [['7.0.3', '']], 'choices': ['pblock'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_pblock_obj'),
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
