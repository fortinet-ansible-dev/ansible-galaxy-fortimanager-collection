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
module: fmgr_application_group
short_description: Configure firewall application groups.
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
    application_group:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application:
                type: raw
                description: (list) Application ID list.
            category:
                type: raw
                description: (list) Application category ID list.
            comment:
                type: str
                description: Comment
            name:
                type: str
                description: Application group name.
                required: true
            type:
                type: str
                description: Application group type.
                choices: ['application', 'category', 'filter']
            behavior:
                type: raw
                description: (list or str) Application behavior filter.
            popularity:
                type: list
                elements: str
                description: Application popularity filter
                choices: ['1', '2', '3', '4', '5']
            protocols:
                type: raw
                description: (list or str) Application protocol filter.
            risk:
                type: raw
                description: (list) Risk, or impact, of allowing traffic from this application to occur
            technology:
                type: raw
                description: (list or str) Application technology filter.
            vendor:
                type: raw
                description: (list or str) Application vendor filter.
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
    - name: Configure firewall application groups.
      fortinet.fortimanager.fmgr_application_group:
        adom: ansible
        state: present
        application_group:
          comment: "ansible-test-comment"
          name: "ansible-test"
          type: application # <value in [application, category]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the application groups
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "application_group"
          params:
            adom: "ansible"
            group: "your_value"
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
        '/pm/config/adom/{adom}/obj/application/group',
        '/pm/config/global/obj/application/group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'application_group': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'application': {'type': 'raw'},
                'category': {'type': 'raw'},
                'comment': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'type': {'choices': ['application', 'category', 'filter'], 'type': 'str'},
                'behavior': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'popularity': {'v_range': [['7.0.0', '']], 'type': 'list', 'choices': ['1', '2', '3', '4', '5'], 'elements': 'str'},
                'protocols': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'risk': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'technology': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'vendor': {'v_range': [['7.0.0', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_group'),
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
