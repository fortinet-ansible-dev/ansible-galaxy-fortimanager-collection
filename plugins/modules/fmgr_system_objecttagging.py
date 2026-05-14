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
module: fmgr_system_objecttagging
short_description: Configure object tagging.
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
    system_objecttagging:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address:
                type: str
                description: Address.
                choices: ['optional', 'mandatory', 'disable']
            category:
                type: str
                description: Tag Category.
                required: true
            color:
                type: int
                description: Color of icon on the GUI.
            device:
                type: str
                description: Device.
                choices: ['optional', 'mandatory', 'disable']
            interface:
                type: str
                description: Interface.
                choices: ['optional', 'mandatory', 'disable']
            multiple:
                type: str
                description: Allow multiple tag selection.
                choices: ['disable', 'enable']
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
    - name: Configure object tagging.
      fortinet.fortimanager.fmgr_system_objecttagging:
        bypass_validation: false
        adom: ansible
        state: present
        system_objecttagging:
          address: optional # <value in [optional, mandatory, disable]>
          category: "ansible-category" # need a valid category name
          color: 0
          device: optional # <value in [optional, mandatory, disable]>
          interface: optional # <value in [optional, mandatory, disable]>
          multiple: enable
          tags: ["ansible-category", "ansible", "ansible1"]

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the object taggings
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_objecttagging"
          params:
            adom: "ansible"
            object_tagging: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/object-tagging',
        '/pm/config/global/obj/system/object-tagging'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_objecttagging': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'address': {'choices': ['optional', 'mandatory', 'disable'], 'type': 'str'},
                'category': {'required': True, 'type': 'str'},
                'color': {'type': 'int'},
                'device': {'choices': ['optional', 'mandatory', 'disable'], 'type': 'str'},
                'interface': {'choices': ['optional', 'mandatory', 'disable'], 'type': 'str'},
                'multiple': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_objecttagging'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'category', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
