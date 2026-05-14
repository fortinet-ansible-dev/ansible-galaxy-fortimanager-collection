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
module: fmgr_system_passwordpolicy
short_description: Password policy.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_passwordpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            change_4_characters:
                aliases: ['change-4-characters']
                type: str
                description:
                    - Enable/disable changing at least 4 characters for new password.
                    - disable - Disable changing at least 4 characters for new password.
                    - enable - Enable changing at least 4 characters for new password.
                choices: ['disable', 'enable']
            expire:
                type: int
                description: Number of days after which admin users password will expire
            minimum_length:
                aliases: ['minimum-length']
                type: int
                description: Minimum password length.
            must_contain:
                aliases: ['must-contain']
                type: list
                elements: str
                description:
                    - Password character requirements.
                    - upper-case-letter - Require password to contain upper case letter.
                    - lower-case-letter - Require password to contain lower case letter.
                    - number - Require password to contain number.
                    - non-alphanumeric - Require password to contain non-alphanumeric characters.
                choices: ['upper-case-letter', 'lower-case-letter', 'number', 'non-alphanumeric']
            status:
                type: str
                description:
                    - Enable/disable password policy.
                    - disable - Disable password policy.
                    - enable - Enable password policy.
                choices: ['disable', 'enable']
            password_history:
                aliases: ['password-history']
                type: int
                description: Number of unique new passwords that must be used before old password can be reused
            login_lockout_upon_downgrade:
                aliases: ['login-lockout-upon-downgrade']
                type: str
                description:
                    - Enable/disable administrative user login lockout upon downgrade
                    - disable - Disable administrative user login lockout upon downgrade.
                    - enable - Enable administrative user login lockout upon downgrade.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Password policy.
      fortinet.fortimanager.fmgr_system_passwordpolicy:
        # workspace_locking_adom: <global or your adom name>
        system_passwordpolicy:
          # change_4_characters: <value in [disable, enable]>
          # expire: <integer>
          # minimum_length: <integer>
          # must_contain: ["upper-case-letter", "lower-case-letter", "number", "non-alphanumeric"]
          # status: <value in [disable, enable]>
          # password_history: <integer>
          # login_lockout_upon_downgrade: <value in [disable, enable]>
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
        '/cli/global/system/password-policy'
    ]
    module_arg_spec = {
        'system_passwordpolicy': {
            'type': 'dict', 'v_range': [['6.0.0', '']], 'no_log': False,
            'options': {
                'change-4-characters': {'choices': ['disable', 'enable'], 'type': 'str'},
                'expire': {'type': 'int'},
                'minimum-length': {'type': 'int'},
                'must-contain': {'type': 'list', 'choices': ['upper-case-letter', 'lower-case-letter', 'number', 'non-alphanumeric'], 'elements': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'password-history': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'},
                'login-lockout-upon-downgrade': {
                    'v_range': [['7.2.11', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_passwordpolicy'),
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
