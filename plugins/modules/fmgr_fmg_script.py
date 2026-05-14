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
module: fmgr_fmg_script
short_description: Fmg script
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
    fmg_script:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            content:
                type: str
                description: Content.
            desc:
                type: str
                description: Desc.
            filter_build:
                type: int
                description: Filter build.
            filter_device:
                type: int
                description: Filter device.
            filter_hostname:
                type: str
                description: Filter hostname.
            filter_ostype:
                type: int
                description: Filter ostype.
            filter_osver:
                type: int
                description: Filter osver.
            filter_platform:
                type: str
                description: Filter platform.
            filter_serial:
                type: str
                description: Filter serial.
            member:
                type: list
                elements: str
                description: Member.
            name:
                type: str
                description: Name.
                required: true
            schedule:
                type: list
                elements: dict
                description: Schedule.
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
            target:
                type: str
                description: Target.
                choices: ['devdb', 'remote', 'adomdb']
            type:
                type: str
                description: Type.
                choices: ['cli', 'tcl', 'cligrp', 'tclgrp', 'jinja']
'''

EXAMPLES = '''
- name: Create and run script (For FMG 7.6.5+)
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    fmg_adom: "root"
    script_name: "your_script_name"
    device_name: "your_device_name"
    device_vdom: "root"
    state: "present"
  tasks:
    # For FMG 7.6.4 and earlier, use fmgr_dvmdb_script.
    # For FMG 7.6.5 and later, use fmgr_fmg_script.
    - name: Create a script (For FMG 7.6.5+)
      fortinet.fortimanager.fmgr_fmg_script:
        state: "{{ state }}"
        adom: "{{ fmg_adom }}"
        fmg_script:
          name: "{{ script_name }}"
          content: |
            config system global
                set remoteauthtimeout 80
            end
          type: cli
          desc: A script created via Ansible
          target: devdb
    - name: Run the Script
      fortinet.fortimanager.fmgr_dvmdb_script_execute:
        adom: "{{ fmg_adom }}"
        dvmdb_script_execute:
          adom: "{{ fmg_adom }}"
          script: "{{ script_name }}"
          scope:
            - name: "{{ device_name }}"
              vdom: "{{ device_vdom }}"
      register: running_task
    - name: Inspect the Task Status
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ running_task.meta.response_data.task }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 3
      failed_when: taskinfo.meta.response_data.state == 'error'
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
        '/pm/config/adom/{adom}/obj/fmg/script',
        '/pm/config/global/obj/fmg/script'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fmg_script': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'content': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'desc': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'filter_build': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'filter_device': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'filter_hostname': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'filter_ostype': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'filter_osver': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'filter_platform': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'filter_serial': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'member': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.6.5', '']], 'required': True, 'type': 'str'},
                'schedule': {
                    'v_range': [['7.6.5', '']],
                    'type': 'list',
                    'options': {
                        'datetime': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'day-of-week': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'device': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'run-on-db': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'timestamp': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'type': {'v_range': [['7.6.5', '']], 'choices': ['auto', 'onetime', 'daily', 'weekly', 'monthly'], 'type': 'str'},
                        'user': {'v_range': [['7.6.5', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'target': {'v_range': [['7.6.5', '']], 'choices': ['devdb', 'remote', 'adomdb'], 'type': 'str'},
                'type': {'v_range': [['7.6.5', '']], 'choices': ['cli', 'tcl', 'cligrp', 'tclgrp', 'jinja'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmg_script'),
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
