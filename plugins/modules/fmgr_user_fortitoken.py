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
module: fmgr_user_fortitoken
short_description: Configure FortiToken.
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
    user_fortitoken:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            license:
                type: str
                description: Mobile token license.
            os_ver:
                aliases: ['os-ver']
                type: str
                description: Device Mobile Version.
            reg_id:
                aliases: ['reg-id']
                type: str
                description: Device Reg ID.
            serial_number:
                aliases: ['serial-number']
                type: str
                description: Serial number.
                required: true
            status:
                type: str
                description: Status
                choices: ['lock', 'active']
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
    - name: Configure FortiToken.
      fortinet.fortimanager.fmgr_user_fortitoken:
        bypass_validation: false
        adom: ansible
        state: present
        user_fortitoken:
          comments: ansible-comment
          serial_number: "your_serial_number" # need a valid FortiToken serial number
          status: lock # <value in [lock, active]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the FortiTokens
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_fortitoken"
          params:
            adom: "ansible"
            fortitoken: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/fortitoken',
        '/pm/config/global/obj/user/fortitoken'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_fortitoken': {
            'type': 'dict', 'v_range': [['6.0.0', '']], 'no_log': False,
            'options': {
                'comments': {'type': 'str'},
                'license': {'type': 'str'},
                'os-ver': {'v_range': [['6.0.0', '6.2.5'], ['6.4.0', '6.4.1'], ['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'reg-id': {'v_range': [['6.0.0', '6.2.5'], ['6.4.0', '6.4.1'], ['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'serial-number': {'required': True, 'type': 'str'},
                'status': {'choices': ['lock', 'active'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fortitoken'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'serial-number', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
