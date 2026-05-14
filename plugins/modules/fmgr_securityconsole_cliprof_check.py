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
module: fmgr_securityconsole_cliprof_check
short_description: Securityconsole cliprof check
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    securityconsole_cliprof_check:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Source ADOM name.
            cliprof:
                type: str
                description: Cliprof.
            scope:
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
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Securityconsole cliprof check
      fortinet.fortimanager.fmgr_securityconsole_cliprof_check:
        # workspace_locking_adom: <global or your adom name>
        securityconsole_cliprof_check:
          # adom: <string>
          # cliprof: <string>
          # scope:
          #   - name: <string>
          #     vdom: <string>
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
        '/securityconsole/cliprof/check'
    ]
    module_arg_spec = {
        'securityconsole_cliprof_check': {
            'type': 'dict', 'v_range': [['7.0.1', '']],
            'options': {
                'adom': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'cliprof': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'scope': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.2.1', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.2.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_cliprof_check'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_exec()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
