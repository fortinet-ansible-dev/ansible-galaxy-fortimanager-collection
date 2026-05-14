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
module: fmgr_isolator_profile
short_description: Isolator profile
version_added: "2.12.0"
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
    isolator_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comments.
            disclaimer:
                type: str
                description: Disclaimer.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices: ['isolate', 'freeze', 'block', 'allow']
                    id:
                        type: int
                        description: Id.
                    proxy_address:
                        aliases: ['proxy-address']
                        type: list
                        elements: str
                        description: Proxy address.
                    status:
                        type: str
                        description: Status.
                        choices: ['disable', 'enable']
                    copy_paste:
                        aliases: ['copy-paste']
                        type: str
                        description: Copy paste.
                        choices: ['disable', 'enable']
                    right_click:
                        aliases: ['right-click']
                        type: str
                        description: Right click.
                        choices: ['disable', 'enable']
            name:
                type: str
                description: Name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Isolator profile
      fortinet.fortimanager.fmgr_isolator_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        isolator_profile:
          name: "your value" # Required variable, string
          # comments: <string>
          # disclaimer: <string>
          # entries:
          #   - action: <value in [isolate, freeze, block, ...]>
          #     id: <integer>
          #     proxy_address: <list or string>
          #     status: <value in [disable, enable]>
          #     copy_paste: <value in [disable, enable]>
          #     right_click: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/isolator/profile',
        '/pm/config/global/obj/isolator/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'isolator_profile': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'comments': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'disclaimer': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'entries': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.6.4', '']], 'choices': ['isolate', 'freeze', 'block', 'allow'], 'type': 'str'},
                        'id': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'proxy-address': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'copy-paste': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'right-click': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'isolator_profile'),
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
