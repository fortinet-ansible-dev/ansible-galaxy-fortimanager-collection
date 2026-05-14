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
module: fmgr_system_report_autocache
short_description: Report auto-cache settings.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_report_autocache:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            aggressive_schedule:
                aliases: ['aggressive-schedule']
                type: str
                description:
                    - Enable/disable auto-cache on schedule reports aggressively.
                    - disable - Disable the aggressive schedule auto-cache.
                    - enable - Enable the aggressive schedule auto-cache.
                choices: ['disable', 'enable']
            order:
                type: str
                description:
                    - The order of which SQL log table is processed first.
                    - oldest-first - The oldest SQL log table is processed first.
                choices: ['oldest-first']
            status:
                type: str
                description:
                    - Enable/disable sql report auto cache.
                    - disable - Disable the sql report auto-cache.
                    - enable - Enable the sql report auto-cache.
                choices: ['disable', 'enable']
            sche_rpt_only:
                aliases: ['sche-rpt-only']
                type: str
                description:
                    - Enable/disable auto-cache on scheduled reports only.
                    - disable - Disable auto-cache on scheduled report only.
                    - enable - Enable auto-cache on scheduled report only.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Report auto-cache settings.
      fortinet.fortimanager.fmgr_system_report_autocache:
        # workspace_locking_adom: <global or your adom name>
        system_report_autocache:
          # aggressive_schedule: <value in [disable, enable]>
          # order: <value in [oldest-first]>
          # status: <value in [disable, enable]>
          # sche_rpt_only: <value in [disable, enable]>
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
        '/cli/global/system/report/auto-cache'
    ]
    module_arg_spec = {
        'system_report_autocache': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'aggressive-schedule': {'choices': ['disable', 'enable'], 'type': 'str'},
                'order': {'choices': ['oldest-first'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sche-rpt-only': {'v_range': [['7.0.8', '7.0.16'], ['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_report_autocache'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
