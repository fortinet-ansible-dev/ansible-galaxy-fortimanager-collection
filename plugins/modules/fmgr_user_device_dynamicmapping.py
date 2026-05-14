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
module: fmgr_user_device_dynamicmapping
short_description: Configure devices.
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
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    user_device_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
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
            avatar:
                type: str
                description: Avatar.
            category:
                type: str
                description: Category.
                choices: ['none', 'android-device', 'blackberry-device', 'fortinet-device',
                          'ios-device', 'windows-device', 'amazon-device']
            comment:
                type: str
                description: Comment.
            mac:
                type: str
                description: Mac.
            master_device:
                aliases: ['master-device']
                type: str
                description: Master device.
            tags:
                type: raw
                description: (list or str) Tags.
            type:
                type: str
                description: Type.
                choices: ['ipad', 'iphone', 'gaming-console', 'blackberry-phone',
                          'blackberry-playbook', 'linux-pc', 'mac', 'windows-pc', 'android-phone',
                          'android-tablet', 'media-streaming', 'windows-phone', 'fortinet-device',
                          'ip-phone', 'router-nat-device', 'other-network-device',
                          'windows-tablet', 'printer', 'forticam', 'fortifone', 'unknown']
            user:
                type: str
                description: User.
            family:
                type: str
                description: Family.
            hardware_vendor:
                aliases: ['hardware-vendor']
                type: str
                description: Hardware vendor.
            hardware_version:
                aliases: ['hardware-version']
                type: str
                description: Hardware version.
            os:
                type: str
                description: Os.
            software_version:
                aliases: ['software-version']
                type: str
                description: Software version.
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
    - name: Configure dynamic mappings
      fortinet.fortimanager.fmgr_user_device_dynamicmapping:
        bypass_validation: false
        adom: ansible
        device: ansible-test-device # alias
        state: present
        user_device_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          category: none # <value in [none, android-device, blackberry-device, ...]>
          comment: ansible-comment
          mac: "00:11:22:33:44:55"
          type: iphone # <value in [ipad, iphone, gaming-console, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_device_dynamicmapping"
          params:
            adom: "ansible"
            device: "ansible-test-device" # alias
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
        '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping',
        '/pm/config/global/obj/user/device/{device}/dynamic_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_device_dynamicmapping': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']],
            'options': {
                '_scope': {
                    'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                        'vdom': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'avatar': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'category': {
                    'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']],
                    'choices': ['none', 'android-device', 'blackberry-device', 'fortinet-device', 'ios-device', 'windows-device', 'amazon-device'],
                    'type': 'str'
                },
                'comment': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'mac': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'master-device': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'raw'},
                'type': {
                    'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']],
                    'choices': [
                        'ipad', 'iphone', 'gaming-console', 'blackberry-phone', 'blackberry-playbook', 'linux-pc', 'mac', 'windows-pc', 'android-phone',
                        'android-tablet', 'media-streaming', 'windows-phone', 'fortinet-device', 'ip-phone', 'router-nat-device', 'other-network-device',
                        'windows-tablet', 'printer', 'forticam', 'fortifone', 'unknown'
                    ],
                    'type': 'str'
                },
                'user': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'family': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'hardware-vendor': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'hardware-version': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'os': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'},
                'software-version': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_device_dynamicmapping'),
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
