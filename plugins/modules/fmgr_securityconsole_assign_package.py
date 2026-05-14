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
module: fmgr_securityconsole_assign_package
short_description: Assign or unassign global policy package to ADOM packages.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    securityconsole_assign_package:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            flags:
                type: list
                elements: str
                description:
                    - cp_all_objs - Assign all objects during global policy assignment.
                    - copy_assigned_pkg - For global policy assignment - copy assigned package from ADOM to device.
                    - unassign - Remove global policy from ADOM.
                choices: ['none', 'cp_all_objs', 'copy_assigned_pkg', 'unassign']
            pkg:
                type: str
                description: Source package path and name.
            target:
                type: list
                elements: dict
                description: Target.
                suboptions:
                    adom:
                        type: str
                        description: Destination ADOM.
                    excluded:
                        type: str
                        description:
                            - disable - Only include the packages listed in the pkg list.
                            - enable - Exclude the package listed in the pkg list, and assign to all other packages in the ADOM.
                        choices: ['disable', 'enable']
                    pkg:
                        type: str
                        description: Destination ADOM policy package path and name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Assign or unassign global policy package to ADOM packages.
      fortinet.fortimanager.fmgr_securityconsole_assign_package:
        # workspace_locking_adom: <global or your adom name>
        securityconsole_assign_package:
          # flags: ["none", "cp_all_objs", "copy_assigned_pkg", "unassign"]
          # pkg: <string>
          # target:
          #   - adom: <string>
          #     excluded: <value in [disable, enable]>
          #     pkg: <string>
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
        '/securityconsole/assign/package'
    ]
    module_arg_spec = {
        'securityconsole_assign_package': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'flags': {'type': 'list', 'choices': ['none', 'cp_all_objs', 'copy_assigned_pkg', 'unassign'], 'elements': 'str'},
                'pkg': {'type': 'str'},
                'target': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'excluded': {'choices': ['disable', 'enable'], 'type': 'str'}, 'pkg': {'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_assign_package'),
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
