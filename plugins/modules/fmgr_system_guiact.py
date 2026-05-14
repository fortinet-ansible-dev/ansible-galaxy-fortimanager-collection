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
module: fmgr_system_guiact
short_description: System settings through GUI.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_guiact:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            backup_all:
                type: str
                description: Backup all settings.
            backup_conf:
                type: str
                description: Backup config file.
            eventlog_msg:
                type: str
                description: Write event log.
            eventlog_path:
                type: str
                description: Event log path.
            reboot:
                type: int
                description: Reboot system.
            reset2default:
                type: int
                description: Reset to factory default.
            restore_all:
                type: str
                description: Restore all settings.
            restore_conf:
                type: str
                description: Restore config file.
            time:
                type: str
                description: Time.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: System settings through GUI.
      fortinet.fortimanager.fmgr_system_guiact:
        # workspace_locking_adom: <global or your adom name>
        system_guiact:
          # backup_all: <string>
          # backup_conf: <string>
          # eventlog_msg: <string>
          # eventlog_path: <string>
          # reboot: <integer>
          # reset2default: <integer>
          # restore_all: <string>
          # restore_conf: <string>
          # time: <string>
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
        '/cli/global/system/guiact'
    ]
    module_arg_spec = {
        'system_guiact': {
            'type': 'dict', 'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']],
            'options': {
                'backup_all': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'backup_conf': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'eventlog_msg': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'eventlog_path': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'reboot': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'reset2default': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'restore_all': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'restore_conf': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'time': {'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_guiact'),
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
