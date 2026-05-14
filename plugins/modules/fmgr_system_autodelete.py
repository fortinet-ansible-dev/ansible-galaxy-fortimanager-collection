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
module: fmgr_system_autodelete
short_description: Automatic deletion policy for logs, reports, archived, and quarantined files.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_autodelete:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dlp_files_auto_deletion:
                aliases: ['dlp-files-auto-deletion']
                type: dict
                description: Dlp files auto deletion.
                suboptions:
                    retention:
                        type: str
                        description:
                            - Automatic deletion in days, weeks, or months.
                            - days - Auto-delete data older than
                            - weeks - Auto-delete data older than
                            - months - Auto-delete data older than
                        choices: ['days', 'weeks', 'months']
                    runat:
                        type: int
                        description: Automatic deletion run at
                    status:
                        type: str
                        description:
                            - Enable/disable automatic deletion.
                            - disable - Disable automatic deletion.
                            - enable - Enable automatic deletion.
                        choices: ['disable', 'enable']
                    value:
                        type: int
                        description: Automatic deletion in x days, weeks, or months.
            log_auto_deletion:
                aliases: ['log-auto-deletion']
                type: dict
                description: Log auto deletion.
                suboptions:
                    retention:
                        type: str
                        description:
                            - Automatic deletion in days, weeks, or months.
                            - days - Auto-delete data older than
                            - weeks - Auto-delete data older than
                            - months - Auto-delete data older than
                        choices: ['days', 'weeks', 'months']
                    runat:
                        type: int
                        description: Automatic deletion run at
                    status:
                        type: str
                        description:
                            - Enable/disable automatic deletion.
                            - disable - Disable automatic deletion.
                            - enable - Enable automatic deletion.
                        choices: ['disable', 'enable']
                    value:
                        type: int
                        description: Automatic deletion in x days, weeks, or months.
            quarantine_files_auto_deletion:
                aliases: ['quarantine-files-auto-deletion']
                type: dict
                description: Quarantine files auto deletion.
                suboptions:
                    retention:
                        type: str
                        description:
                            - Automatic deletion in days, weeks, or months.
                            - days - Auto-delete data older than
                            - weeks - Auto-delete data older than
                            - months - Auto-delete data older than
                        choices: ['days', 'weeks', 'months']
                    runat:
                        type: int
                        description: Automatic deletion run at
                    status:
                        type: str
                        description:
                            - Enable/disable automatic deletion.
                            - disable - Disable automatic deletion.
                            - enable - Enable automatic deletion.
                        choices: ['disable', 'enable']
                    value:
                        type: int
                        description: Automatic deletion in x days, weeks, or months.
            report_auto_deletion:
                aliases: ['report-auto-deletion']
                type: dict
                description: Report auto deletion.
                suboptions:
                    retention:
                        type: str
                        description:
                            - Automatic deletion in days, weeks, or months.
                            - days - Auto-delete data older than
                            - weeks - Auto-delete data older than
                            - months - Auto-delete data older than
                        choices: ['days', 'weeks', 'months']
                    runat:
                        type: int
                        description: Automatic deletion run at
                    status:
                        type: str
                        description:
                            - Enable/disable automatic deletion.
                            - disable - Disable automatic deletion.
                            - enable - Enable automatic deletion.
                        choices: ['disable', 'enable']
                    value:
                        type: int
                        description: Automatic deletion in x days, weeks, or months.
            status_fake:
                aliases: ['status-fake']
                type: int
                description: Fake value for the menu to work.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Automatic deletion policy for logs, reports, archived, and quarantined files.
      fortinet.fortimanager.fmgr_system_autodelete:
        # workspace_locking_adom: <global or your adom name>
        system_autodelete:
          # dlp_files_auto_deletion:
          #   retention: <value in [days, weeks, months]>
          #   runat: <integer>
          #   status: <value in [disable, enable]>
          #   value: <integer>
          # log_auto_deletion:
          #   retention: <value in [days, weeks, months]>
          #   runat: <integer>
          #   status: <value in [disable, enable]>
          #   value: <integer>
          # quarantine_files_auto_deletion:
          #   retention: <value in [days, weeks, months]>
          #   runat: <integer>
          #   status: <value in [disable, enable]>
          #   value: <integer>
          # report_auto_deletion:
          #   retention: <value in [days, weeks, months]>
          #   runat: <integer>
          #   status: <value in [disable, enable]>
          #   value: <integer>
          # status_fake: <integer>
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
        '/cli/global/system/auto-delete'
    ]
    module_arg_spec = {
        'system_autodelete': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'dlp-files-auto-deletion': {
                    'type': 'dict',
                    'options': {
                        'retention': {'choices': ['days', 'weeks', 'months'], 'type': 'str'},
                        'runat': {'type': 'int'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'value': {'type': 'int'}
                    }
                },
                'log-auto-deletion': {
                    'type': 'dict',
                    'options': {
                        'retention': {'choices': ['days', 'weeks', 'months'], 'type': 'str'},
                        'runat': {'type': 'int'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'value': {'type': 'int'}
                    }
                },
                'quarantine-files-auto-deletion': {
                    'type': 'dict',
                    'options': {
                        'retention': {'choices': ['days', 'weeks', 'months'], 'type': 'str'},
                        'runat': {'type': 'int'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'value': {'type': 'int'}
                    }
                },
                'report-auto-deletion': {
                    'type': 'dict',
                    'options': {
                        'retention': {'choices': ['days', 'weeks', 'months'], 'type': 'str'},
                        'runat': {'type': 'int'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'value': {'type': 'int'}
                    }
                },
                'status-fake': {'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_autodelete'),
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
