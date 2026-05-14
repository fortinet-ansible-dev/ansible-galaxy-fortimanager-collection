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
module: fmgr_videofilter_profile_fortiguardcategory
short_description: Configure FortiGuard categories.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    videofilter_profile_fortiguardcategory:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            filters:
                type: list
                elements: dict
                description: Filters.
                suboptions:
                    action:
                        type: str
                        description: VideoFilter action.
                        choices: ['block', 'bypass', 'monitor', 'allow']
                    category_id:
                        aliases: ['category-id']
                        type: int
                        description: Category ID.
                    id:
                        type: int
                        description: ID.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiGuard categories.
      fortinet.fortimanager.fmgr_videofilter_profile_fortiguardcategory:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        videofilter_profile_fortiguardcategory:
          # filters:
          #   - action: <value in [block, bypass, monitor, ...]>
          #     category_id: <integer>
          #     id: <integer>
          #     log: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category',
        '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'videofilter_profile_fortiguardcategory': {
            'type': 'dict', 'v_range': [['7.0.0', '']],
            'options': {
                'filters': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.0.0', '']], 'choices': ['block', 'bypass', 'monitor', 'allow'], 'type': 'str'},
                        'category-id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'log': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'videofilter_profile_fortiguardcategory'),
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
