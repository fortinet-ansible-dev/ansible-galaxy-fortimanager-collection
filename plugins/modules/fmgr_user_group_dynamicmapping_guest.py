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
module: fmgr_user_group_dynamicmapping_guest
short_description: Guest User.
version_added: "2.1.0"
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
    group:
        description: The parameter (group) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    user_group_dynamicmapping_guest:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            company:
                type: str
                description: Set the action for the company guest user field.
            email:
                type: str
                description: Email.
            expiration:
                type: str
                description: Expire time.
            group:
                type: str
                description: Group.
            id:
                type: int
                description: Guest ID.
                required: true
            mobile_phone:
                aliases: ['mobile-phone']
                type: str
                description: Mobile phone.
            name:
                type: str
                description: Guest name.
            password:
                type: raw
                description: (list) Guest password.
            sponsor:
                type: str
                description: Set the action for the sponsor guest user field.
            user_id:
                aliases: ['user-id']
                type: str
                description: Guest ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Guest User.
      fortinet.fortimanager.fmgr_user_group_dynamicmapping_guest:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        group: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        user_group_dynamicmapping_guest:
          id: 0 # Required variable, integer
          # comment: <string>
          # company: <string>
          # email: <string>
          # expiration: <string>
          # group: <string>
          # mobile_phone: <string>
          # name: <string>
          # password: <list or string>
          # sponsor: <string>
          # user_id: <string>
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
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest',
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'group': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_group_dynamicmapping_guest': {
            'type': 'dict', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'comment': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'company': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'email': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'expiration': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'group': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'id': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'required': True, 'type': 'int'},
                'mobile-phone': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'name': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'password': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'no_log': True, 'type': 'raw'},
                'sponsor': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'user-id': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_group_dynamicmapping_guest'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
