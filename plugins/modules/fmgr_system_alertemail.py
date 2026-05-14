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
module: fmgr_system_alertemail
short_description: Configure alertemail.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_alertemail:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authentication:
                type: str
                description:
                    - Enable/disable authentication.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            fromaddress:
                type: str
                description: SMTP from address.
            fromname:
                type: str
                description: SMTP from user.
            smtppassword:
                type: raw
                description: (list) SMTP server password.
            smtpport:
                type: int
                description: SMTP server port.
            smtpserver:
                type: str
                description: SMTP server address.
            smtpuser:
                type: str
                description: SMTP server user.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure alertemail.
      fortinet.fortimanager.fmgr_system_alertemail:
        # workspace_locking_adom: <global or your adom name>
        system_alertemail:
          # authentication: <value in [disable, enable]>
          # fromaddress: <string>
          # fromname: <string>
          # smtppassword: <list or string>
          # smtpport: <integer>
          # smtpserver: <string>
          # smtpuser: <string>
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
        '/cli/global/system/alertemail'
    ]
    module_arg_spec = {
        'system_alertemail': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fromaddress': {'type': 'str'},
                'fromname': {'type': 'str'},
                'smtppassword': {'no_log': True, 'type': 'raw'},
                'smtpport': {'type': 'int'},
                'smtpserver': {'type': 'str'},
                'smtpuser': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_alertemail'),
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
