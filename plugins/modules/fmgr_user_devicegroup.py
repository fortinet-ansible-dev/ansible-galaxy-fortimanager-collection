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
module: fmgr_user_devicegroup
short_description: Configure device groups.
version_added: "2.0.0"
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
    user_devicegroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _if_unmanaged:
                type: int
                description: If unmanaged.
            comment:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _if_unmanaged:
                        type: int
                        description: If unmanaged.
                    _scope:
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
                    comment:
                        type: str
                        description: Comment.
                    member:
                        type: list
                        elements: str
                        description: Member.
            member:
                type: list
                elements: str
                description: Device group member.
            name:
                type: str
                description: Device group name.
                required: true
            tagging:
                type: list
                elements: dict
                description: Tagging.
                suboptions:
                    category:
                        type: str
                        description: Tag category.
                    name:
                        type: str
                        description: Tagging entry name.
                    tags:
                        type: raw
                        description: (list) Tags.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Create User Device Group
      fortinet.fortimanager.fmgr_user_devicegroup:
        adom: ansible
        state: "present"
        user_devicegroup:
          name: ansible-test

    - name: Configure dynamic mappings of device group
      fortinet.fortimanager.fmgr_user_devicegroup_dynamicmapping:
        bypass_validation: false
        adom: ansible
        device_group: ansible-test # name
        state: present
        user_devicegroup_dynamicmapping:
          _if_unmanaged: 10
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          comment: ansible-comment
          member: ios-device
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
        '/pm/config/adom/{adom}/obj/user/device-group',
        '/pm/config/global/obj/user/device-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_devicegroup': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1']],
            'options': {
                '_if_unmanaged': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                'comment': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        '_if_unmanaged': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        '_scope': {
                            'v_range': [['6.0.0', '7.2.1']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                                'vdom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'comment': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'member': {'v_range': [['6.0.0', '7.2.1']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'member': {'v_range': [['6.0.0', '7.2.1']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['6.0.0', '7.2.1']], 'required': True, 'type': 'str'},
                'tagging': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'name': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'tags': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_devicegroup'),
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
