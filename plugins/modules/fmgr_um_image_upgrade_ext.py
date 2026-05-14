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
module: fmgr_um_image_upgrade_ext
short_description: Update the firmware of specific device.
version_added: "2.2.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    um_image_upgrade_ext:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            create_task:
                type: str
                description: Create task.
            device:
                type: list
                elements: dict
                description: Device.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            flags:
                type: str
                description: Flags.
                choices: ['f_boot_alt_partition', 'f_skip_retrieve', 'f_skip_multi_steps',
                          'f_skip_fortiguard_img', 'f_preview']
            image:
                type: str
                description: Support version with a build number.
            schedule_time:
                type: str
                description: Schedule time.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Update the firmware of specific device.
      fortinet.fortimanager.fmgr_um_image_upgrade_ext:
        # workspace_locking_adom: <global or your adom name>
        um_image_upgrade_ext:
          # create_task: <string>
          # device:
          #   - name: <string>
          #     vdom: <string>
          # flags: <value in [f_boot_alt_partition, f_skip_retrieve, f_skip_multi_steps, ...]>
          # image: <string>
          # schedule_time: <string>
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
        '/um/image/upgrade/ext'
    ]
    module_arg_spec = {
        'um_image_upgrade_ext': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'create_task': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'device': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.2.1', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.2.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'flags': {
                    'v_range': [['7.2.1', '']],
                    'choices': ['f_boot_alt_partition', 'f_skip_retrieve', 'f_skip_multi_steps', 'f_skip_fortiguard_img', 'f_preview'],
                    'type': 'str'
                },
                'image': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'schedule_time': {'v_range': [['7.2.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'um_image_upgrade_ext'),
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
