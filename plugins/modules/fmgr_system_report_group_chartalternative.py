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
module: fmgr_system_report_group_chartalternative
short_description: Chart alternatives.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    group:
        description: The parameter (group) in requested url.
        type: str
        required: true
    system_report_group_chartalternative:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            chart_name:
                aliases: ['chart-name']
                type: str
                description: Chart name.
                required: true
            chart_replace:
                aliases: ['chart-replace']
                type: str
                description: Chart replacement.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Chart alternatives.
      fortinet.fortimanager.fmgr_system_report_group_chartalternative:
        # workspace_locking_adom: <global or your adom name>
        group: <your own value>
        state: present # <value in [present, absent]>
        system_report_group_chartalternative:
          chart_name: "your value" # Required variable, string
          # chart_replace: <string>
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
        '/cli/global/system/report/group/{group}/chart-alternative'
    ]
    module_arg_spec = {
        'group': {'required': True, 'type': 'str'},
        'system_report_group_chartalternative': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'chart-name': {'required': True, 'type': 'str'}, 'chart-replace': {'type': 'str'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_report_group_chartalternative'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'chart-name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
