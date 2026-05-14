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
module: fmgr_dvmdb_script_execute
short_description: Run script.
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    dvmdb_script_execute:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Adom.
            package:
                type: str
                description: Package.
            scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            script:
                type: str
                description: Script name.
            pblock:
                type: str
                description: Pblock.
'''

EXAMPLES = '''
- name: Apply a script to device (For FMG <= 7.6.4)
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
    device_adom: "root"
    script_name: "FooScript"
    device_name: "CustomHostName"
    device_vdom: "root"
  tasks:
    # For FMG 7.6.4 and earlier, use fmgr_dvmdb_script.
    # For FMG 7.6.5 and later, use fmgr_fmg_script.
    - name: Create a Script to later execute
      fortinet.fortimanager.fmgr_dvmdb_script:
        adom: "{{ device_adom }}"
        state: "present"
        dvmdb_script:
          name: "{{ script_name }}"
          desc: "A script created via Ansible"
          content: |
            config system global
                set remoteauthtimeout 80
            end
          type: "cli"
    - name: Run the Script
      fortinet.fortimanager.fmgr_dvmdb_script_execute:
        adom: "{{ device_adom }}"
        dvmdb_script_execute:
          adom: "{{ device_adom }}"
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

- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Run script.
      fortinet.fortimanager.fmgr_dvmdb_script_execute:
        bypass_validation: false
        adom: ansible
        dvmdb_script_execute:
          adom: ansible
          package: "your_value"
          scope:
            - name: Ansible-test
              vdom: root
          script: ansible-test

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
        '/dvmdb/adom/{adom}/script/execute',
        '/dvmdb/global/script/execute',
        '/dvmdb/script/execute'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'dvmdb_script_execute': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'package': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'scope': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'vdom': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'script': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'pblock': {'v_range': [['7.0.10', '7.0.16'], ['7.2.5', '7.2.12'], ['7.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_script_execute'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_exec()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
