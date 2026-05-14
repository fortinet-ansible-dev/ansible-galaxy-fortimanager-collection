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
module: fmgr_system_admin_user_restrictdevvdom
short_description: Restricted to these devices/VDOMs.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    user:
        description: The parameter (user) in requested url.
        type: str
        required: true
    system_admin_user_restrictdevvdom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dev_vdom:
                aliases: ['dev-vdom']
                type: str
                description: Device or device VDOM.
                required: true
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
    - name: Restricted to these devices/VDOMs.
      fortinet.fortimanager.fmgr_system_admin_user_restrictdevvdom:
        bypass_validation: false
        user: ansible-test # userid
        state: present
        system_admin_user_restrictdevvdom:
          dev_vdom: FGT_AWS

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the restricted devices/VDOMs of user
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_user_restrictdevvdom"
          params:
            user: "ansible-test" # userid
            restrict_dev_vdom: "your_value"
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
        '/cli/global/system/admin/user/{user}/restrict-dev-vdom'
    ]
    module_arg_spec = {
        'user': {'required': True, 'type': 'str'},
        'system_admin_user_restrictdevvdom': {
            'type': 'dict', 'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']],
            'options': {'dev-vdom': {'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']], 'required': True, 'type': 'str'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_user_restrictdevvdom'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'dev-vdom', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
