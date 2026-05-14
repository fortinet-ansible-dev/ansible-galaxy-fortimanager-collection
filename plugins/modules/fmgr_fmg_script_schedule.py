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
module: fmgr_fmg_script_schedule
short_description: Fmg script schedule
version_added: "2.13.0"
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
    script:
        description: The parameter (script) in requested url.
        type: str
        required: true
    fmg_script_schedule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            datetime:
                type: str
                description: Datetime.
            day_of_week:
                aliases: ['day-of-week']
                type: int
                description: Day of week.
            device:
                type: int
                description: Device.
            run_on_db:
                aliases: ['run-on-db']
                type: int
                description: Run on db.
            timestamp:
                type: int
                description: Timestamp.
            type:
                type: str
                description: Type.
                choices: ['auto', 'onetime', 'daily', 'weekly', 'monthly']
            user:
                type: str
                description: User.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Fmg script schedule
      fortinet.fortimanager.fmgr_fmg_script_schedule:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        script: <your own value>
        state: present # <value in [present, absent]>
        fmg_script_schedule:
          # datetime: <string>
          # day_of_week: <integer>
          # device: <integer>
          # run_on_db: <integer>
          # timestamp: <integer>
          # type: <value in [auto, onetime, daily, ...]>
          # user: <string>
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
        '/pm/config/adom/{adom}/obj/fmg/script/{script}/schedule',
        '/pm/config/global/obj/fmg/script/{script}/schedule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'script': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fmg_script_schedule': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'datetime': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'day-of-week': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'device': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'run-on-db': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'timestamp': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'type': {'v_range': [['7.6.5', '']], 'choices': ['auto', 'onetime', 'daily', 'weekly', 'monthly'], 'type': 'str'},
                'user': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmg_script_schedule'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
