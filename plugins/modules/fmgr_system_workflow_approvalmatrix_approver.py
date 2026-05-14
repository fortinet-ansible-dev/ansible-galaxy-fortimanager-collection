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
module: fmgr_system_workflow_approvalmatrix_approver
short_description: Approver.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    approval-matrix:
        description: Deprecated, please use "approval_matrix"
        type: str
    approval_matrix:
        description: The parameter (approval-matrix) in requested url.
        type: str
    system_workflow_approvalmatrix_approver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            member:
                type: str
                description: Member of approver.
            seq_num:
                type: int
                description: Entry number.
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
    - name: Approver.
      fortinet.fortimanager.fmgr_system_workflow_approvalmatrix_approver:
        bypass_validation: false
        approval_matrix: ansible
        state: present
        system_workflow_approvalmatrix_approver:
          member: ansible-test-member
          seq_num: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the approvers of workflow approval matrix
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_workflow_approvalmatrix_approver"
          params:
            approval_matrix: "ansible"
            approver: "your_value"
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
        '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver'
    ]
    module_arg_spec = {
        'approval-matrix': {'type': 'str', 'api_name': 'approval_matrix'},
        'approval_matrix': {'type': 'str'},
        'system_workflow_approvalmatrix_approver': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'member': {'type': 'str'}, 'seq_num': {'required': True, 'type': 'int'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_workflow_approvalmatrix_approver'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'seq_num', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
