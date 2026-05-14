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
module: fmgr_user_group_guest
short_description: Guest User.
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
    group:
        description: The parameter (group) in requested url.
        type: str
        required: true
    user_group_guest:
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
                required: true
            group:
                type: str
                description: Guest name.
            id:
                type: int
                description: Guest ID.
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
    - name: Guest User.
      fortinet.fortimanager.fmgr_user_group_guest:
        bypass_validation: false
        adom: FortiCarrier
        group: ansible-test-group # name
        state: present
        user_group_guest:
          comment: ansible-comment
          email: test@fortinet.com
          name: ansible-test-guest
          password: fortinet
          user_id: Email

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the guest users
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_group_guest" # Note: this session will been shown only if the Type parameter in User Grup is 'GUEST'
          params:
            adom: "FortiCarrier"
            group: "ansible-test-group" # name
            guest: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/group/{group}/guest',
        '/pm/config/global/obj/user/group/{group}/guest'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'group': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_group_guest': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'company': {'type': 'str'},
                'email': {'type': 'str'},
                'expiration': {'type': 'str'},
                'mobile-phone': {'type': 'str'},
                'name': {'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'sponsor': {'type': 'str'},
                'user-id': {'required': True, 'type': 'str'},
                'group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'id': {'v_range': [['6.2.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_group_guest'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'user-id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
