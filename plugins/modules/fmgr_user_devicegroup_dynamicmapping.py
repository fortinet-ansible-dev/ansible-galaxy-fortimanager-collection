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
module: fmgr_user_devicegroup_dynamicmapping
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
    device-group:
        description: Deprecated, please use "device_group"
        type: str
    device_group:
        description: The parameter (device-group) in requested url.
        type: str
    user_devicegroup_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
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
                type: raw
                description: (list or str) Member.
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

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of device group
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_devicegroup_dynamicmapping"
          params:
            adom: "ansible"
            device_group: "ansible-test" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping',
        '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device-group': {'type': 'str', 'api_name': 'device_group'},
        'device_group': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_devicegroup_dynamicmapping': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1']],
            'options': {
                '_if_unmanaged': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                '_scope': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}, 'vdom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'comment': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'member': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_devicegroup_dynamicmapping'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
