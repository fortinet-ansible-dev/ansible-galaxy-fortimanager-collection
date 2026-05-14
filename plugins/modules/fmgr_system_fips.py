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
module: fmgr_system_fips
short_description: Settings for FIPS-CC mode.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_fips:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            entropy_token:
                aliases: ['entropy-token']
                type: str
                description:
                    - Enable/disable entropy token when switching to FIPS mode.
                    - enable - Enable entropy token.
                    - disable - Disable entropy token.
                    - dynamic - Dynamically detect entropy token during bootup.
                choices: ['enable', 'disable', 'dynamic']
            re_seed_interval:
                aliases: ['re-seed-interval']
                type: int
                description: Kernel FIPS-compliant PRNG re-seed interval
            status:
                type: str
                description:
                    - Enable/disable FIPS-CC mode.
                    - disable - Disable FIPS-CC mode.
                    - enable - Enable FIPS-CC mode.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Settings for FIPS-CC mode.
      fortinet.fortimanager.fmgr_system_fips:
        # workspace_locking_adom: <global or your adom name>
        system_fips:
          # entropy_token: <value in [enable, disable, dynamic]>
          # re_seed_interval: <integer>
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
        '/cli/global/system/fips'
    ]
    module_arg_spec = {
        'system_fips': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'entropy-token': {'v_range': [['6.0.0', '7.6.3']], 'choices': ['enable', 'disable', 'dynamic'], 'type': 'str'},
                're-seed-interval': {'v_range': [['6.0.0', '7.6.3']], 'type': 'int'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fips'),
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
