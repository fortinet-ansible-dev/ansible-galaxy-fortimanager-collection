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
module: fmgr_application_list_entries_parameters
short_description: Application parameters.
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
    list:
        description: The parameter (list) in requested url.
        type: str
        required: true
    entries:
        description: The parameter (entries) in requested url.
        type: str
        required: true
    application_list_entries_parameters:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Parameter ID.
                required: true
            value:
                type: str
                description: Parameter value.
            members:
                type: list
                elements: dict
                description: Members.
                suboptions:
                    id:
                        type: int
                        description: Parameter.
                    name:
                        type: str
                        description: Parameter name.
                    value:
                        type: str
                        description: Parameter value.
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
    - name: Application parameters.
      fortinet.fortimanager.fmgr_application_list_entries_parameters:
        adom: ansible
        list: "ansible-test" # name
        entries: "1" # id
        state: present
        application_list_entries_parameters:
          id: 1
          value: "ansible-test-parameter2"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the parameters in the application list entry
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "application_list_entries_parameters"
          params:
            adom: "ansible"
            list: "ansible-test" # name
            entries: "1" # id
            parameters: "your_value"
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
        '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters',
        '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'list': {'required': True, 'type': 'str'},
        'entries': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'application_list_entries_parameters': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'id': {'required': True, 'type': 'int'},
                'value': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'members': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'value': {'v_range': [['6.4.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_list_entries_parameters'),
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
