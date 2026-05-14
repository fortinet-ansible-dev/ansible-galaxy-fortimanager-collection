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
module: fmgr_sys_cloud_orchest
short_description: Sys cloud orchest
version_added: "2.2.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    sys_cloud_orchest:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices: ['deploy', 'undeploy', 'status']
            adom:
                type: str
                description: Adom.
            adom_oid:
                type: int
                description: Adom oid.
            name:
                type: str
                description: Name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Sys cloud orchest
      fortinet.fortimanager.fmgr_sys_cloud_orchest:
        # workspace_locking_adom: <global or your adom name>
        sys_cloud_orchest:
          # action: <value in [deploy, undeploy, status]>
          # adom: <string>
          # adom_oid: <integer>
          # name: <string>
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
        '/sys/cloud/orchest'
    ]
    module_arg_spec = {
        'sys_cloud_orchest': {
            'type': 'dict', 'v_range': [['7.4.0', '']],
            'options': {
                'action': {'v_range': [['7.4.0', '']], 'choices': ['deploy', 'undeploy', 'status'], 'type': 'str'},
                'adom': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'adom_oid': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'sys_cloud_orchest'),
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
