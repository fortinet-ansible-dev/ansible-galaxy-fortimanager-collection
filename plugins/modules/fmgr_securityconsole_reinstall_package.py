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
module: fmgr_securityconsole_reinstall_package
short_description: Re-install a policy package that had been previously installed.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    securityconsole_reinstall_package:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Source ADOM name.
            flags:
                type: list
                elements: str
                description:
                    - cp_all_objs - Assign all objects during global policy assignment.
                    - preview - Generate preview cache only.
                    - generate_rev - Generate new ADOM revision before install.
                    - copy_assigned_pkg - For global policy assignment - copy assigned package from ADOM to device.
                    - unassign - Remove global policy from ADOM.
                    - ifpolicy_only - Only install interface policies.
                    - no_ifpolicy - Install regular policies only - do not install interface policies.
                    - objs_only - Install object
                    - auto_lock_ws - Automatically lock and unlock workspace when performing security console task.
                    - copy_only - Only copy to device db.
                choices: ['none', 'cp_all_objs', 'preview', 'generate_rev', 'copy_assigned_pkg',
                          'unassign', 'ifpolicy_only', 'no_ifpolicy', 'objs_only', 'auto_lock_ws',
                          'check_pkg_st', 'copy_only']
            target:
                type: list
                elements: dict
                description: Target.
                suboptions:
                    pkg:
                        type: str
                        description: Source package path and name.
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
    - name: Re-install a policy package that had been previously installed.
      fortinet.fortimanager.fmgr_securityconsole_reinstall_package:
        # workspace_locking_adom: <global or your adom name>
        securityconsole_reinstall_package:
          # adom: <string>
          # flags: ["none", "cp_all_objs", "preview", "generate_rev", "copy_assigned_pkg",
          #         "unassign", "ifpolicy_only", "no_ifpolicy", "objs_only", "auto_lock_ws",
          #         "check_pkg_st", "copy_only"]
          # target:
          #   - pkg: <string>
          #     scope:
          #       - name: <string>
          #         vdom: <string>
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
        '/securityconsole/reinstall/package'
    ]
    module_arg_spec = {
        'securityconsole_reinstall_package': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'str'},
                'flags': {
                    'type': 'list',
                    'choices': [
                        'none', 'cp_all_objs', 'preview', 'generate_rev', 'copy_assigned_pkg', 'unassign', 'ifpolicy_only', 'no_ifpolicy', 'objs_only',
                        'auto_lock_ws', 'check_pkg_st', 'copy_only'
                    ],
                    'elements': 'str'
                },
                'target': {
                    'type': 'list',
                    'options': {
                        'pkg': {'type': 'str'},
                        'scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_reinstall_package'),
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
