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
module: fmgr_dvmdb_script_scriptschedule
short_description: Script schedule table.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    script:
        description: The parameter (script) in requested url.
        type: str
        required: true
    dvmdb_script_scriptschedule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            datetime:
                type: str
                description:
                    - Indicates the date and time of the schedule.
                    - onetime
                    - daily
                    - weekly
                    - monthly
            day_of_week:
                type: str
                description: Day of week.
                choices: ['unknown', 'sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
            device:
                type: int
                description: Name or id of an existing device in the database.
            name:
                type: str
                description: Name.
                required: true
            run_on_db:
                type: str
                description: Indicates if the scheduled script should be executed on device database.
                choices: ['disable', 'enable']
            type:
                type: str
                description: Type.
                choices: ['auto', 'onetime', 'daily', 'weekly', 'monthly']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Script schedule table.
      fortinet.fortimanager.fmgr_dvmdb_script_scriptschedule:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        script: <your own value>
        state: present # <value in [present, absent]>
        dvmdb_script_scriptschedule:
          name: "your value" # Required variable, string
          # datetime: <string>
          # day_of_week: <value in [unknown, sun, mon, ...]>
          # device: <integer>
          # run_on_db: <value in [disable, enable]>
          # type: <value in [auto, onetime, daily, ...]>
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
        '/dvmdb/adom/{adom}/script/{script}/script_schedule',
        '/dvmdb/global/script/{script}/script_schedule',
        '/dvmdb/script/{script}/script_schedule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'script': {'required': True, 'type': 'str'},
        'dvmdb_script_scriptschedule': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'datetime': {'type': 'str'},
                'day_of_week': {'choices': ['unknown', 'sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], 'type': 'str'},
                'device': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'run_on_db': {'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'choices': ['auto', 'onetime', 'daily', 'weekly', 'monthly'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_script_scriptschedule'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
