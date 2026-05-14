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
module: fmgr_application_custom
short_description: Configure custom application signatures.
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
    application_custom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            behavior:
                type: str
                description: Custom application signature behavior.
            category:
                type: str
                description: Custom application category ID
            comment:
                type: str
                description: Comment.
            id:
                type: int
                description: Id.
            name:
                type: str
                description: Name.
            protocol:
                type: str
                description: Custom application signature protocol.
            signature:
                type: str
                description: The text that makes up the actual custom application signature.
            tag:
                type: str
                description: Signature tag.
                required: true
            technology:
                type: str
                description: Custom application signature technology.
            vendor:
                type: str
                description: Custom application signature vendor.
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
    - name: Configure custom application signatures.
      fortinet.fortimanager.fmgr_application_custom:
        adom: ansible
        state: present
        application_custom:
          behavior: "ansible-test1"
          category: "ansible-test1"
          comment: "ansble-test"
          id: 1000
          name: "ansible-test1"
          protocol: "ansble-test1"
          signature: "ansble-test1"
          tag: "ansble-test-tag"
          technology: "ansble-test"
          vendor: "ansble-test-vendor"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the custom application signatures
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "application_custom"
          params:
            adom: "ansible"
            custom: "your_value"
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
        '/pm/config/adom/{adom}/obj/application/custom',
        '/pm/config/global/obj/application/custom'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'application_custom': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'behavior': {'type': 'str'},
                'category': {'type': 'str'},
                'comment': {'type': 'str'},
                'id': {'type': 'int'},
                'name': {'type': 'str'},
                'protocol': {'type': 'str'},
                'signature': {'type': 'str'},
                'tag': {'required': True, 'type': 'str'},
                'technology': {'type': 'str'},
                'vendor': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_custom'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'tag', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
