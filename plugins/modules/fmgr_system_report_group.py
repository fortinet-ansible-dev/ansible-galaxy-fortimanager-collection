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
module: fmgr_system_report_group
short_description: Report group.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_report_group:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Admin domain name.
            case_insensitive:
                aliases: ['case-insensitive']
                type: str
                description:
                    - Case insensitive.
                    - disable - Disable the case insensitive match.
                    - enable - Enable the case insensitive match.
                choices: ['disable', 'enable']
            chart_alternative:
                aliases: ['chart-alternative']
                type: list
                elements: dict
                description: Chart alternative.
                suboptions:
                    chart_name:
                        aliases: ['chart-name']
                        type: str
                        description: Chart name.
                    chart_replace:
                        aliases: ['chart-replace']
                        type: str
                        description: Chart replacement.
            group_by:
                aliases: ['group-by']
                type: list
                elements: dict
                description: Group by.
                suboptions:
                    var_expression:
                        aliases: ['var-expression']
                        type: str
                        description: Variable expression.
                    var_name:
                        aliases: ['var-name']
                        type: str
                        description: Variable name.
                    var_type:
                        aliases: ['var-type']
                        type: str
                        description:
                            - Variable type.
                            - integer - Integer.
                            - string - String.
                            - enum - Enum.
                            - ip - IP.
                        choices: ['integer', 'string', 'enum', 'ip']
            group_id:
                aliases: ['group-id']
                type: int
                description: Group ID.
                required: true
            report_like:
                aliases: ['report-like']
                type: str
                description: Report pattern.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Report group.
      fortinet.fortimanager.fmgr_system_report_group:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_report_group:
          group_id: 0 # Required variable, integer
          # adom: <string>
          # case_insensitive: <value in [disable, enable]>
          # chart_alternative:
          #   - chart_name: <string>
          #     chart_replace: <string>
          # group_by:
          #   - var_expression: <string>
          #     var_name: <string>
          #     var_type: <value in [integer, string, enum, ...]>
          # report_like: <string>
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
        '/cli/global/system/report/group'
    ]
    module_arg_spec = {
        'system_report_group': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'str'},
                'case-insensitive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'chart-alternative': {'type': 'list', 'options': {'chart-name': {'type': 'str'}, 'chart-replace': {'type': 'str'}}, 'elements': 'dict'},
                'group-by': {
                    'type': 'list',
                    'options': {
                        'var-expression': {'type': 'str'},
                        'var-name': {'type': 'str'},
                        'var-type': {'choices': ['integer', 'string', 'enum', 'ip'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-id': {'required': True, 'type': 'int'},
                'report-like': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_report_group'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'group-id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
