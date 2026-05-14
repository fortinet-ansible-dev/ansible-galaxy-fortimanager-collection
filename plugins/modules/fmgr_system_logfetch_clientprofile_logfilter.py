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
module: fmgr_system_logfetch_clientprofile_logfilter
short_description: Log content filters.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    client-profile:
        description: Deprecated, please use "client_profile"
        type: str
    client_profile:
        description: The parameter (client-profile) in requested url.
        type: str
    system_logfetch_clientprofile_logfilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            field:
                type: str
                description: Field name.
            id:
                type: int
                description: Log filter ID.
                required: true
            oper:
                type: str
                description:
                    - Field filter operator.
                    - no description
                    - no description
                    - contain - Contain
                    - not-contain - Not contain
                    - match - Match
                choices: ['=', '!=', '<', '>', '<=', '>=', 'contain', 'not-contain', 'match']
            value:
                type: str
                description: Field filter operand or free-text matching expression.
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
    - name: Log content filters.
      fortinet.fortimanager.fmgr_system_logfetch_clientprofile_logfilter:
        bypass_validation: false
        client_profile: 1 # id
        state: present
        system_logfetch_clientprofile_logfilter:
          field: 0
          id: 1
          oper: "!=" # <value in [=, !=, <, ...]>
          value: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the log content filters of profile setting
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_logfetch_clientprofile_logfilter"
          params:
            client_profile: "1" # id
            log_filter: "your_value"
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
        '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter'
    ]
    module_arg_spec = {
        'client-profile': {'type': 'str', 'api_name': 'client_profile'},
        'client_profile': {'type': 'str'},
        'system_logfetch_clientprofile_logfilter': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1']],
            'options': {
                'field': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'id': {'v_range': [['6.0.0', '7.2.1']], 'required': True, 'type': 'int'},
                'oper': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['=', '!=', '<', '>', '<=', '>=', 'contain', 'not-contain', 'match'], 'type': 'str'},
                'value': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_logfetch_clientprofile_logfilter'),
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
