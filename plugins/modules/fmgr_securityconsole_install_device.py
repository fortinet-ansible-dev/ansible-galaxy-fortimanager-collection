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
module: fmgr_securityconsole_install_device
short_description: Securityconsole install device
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    securityconsole_install_device:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Source ADOM name.
            dev_rev_comments:
                type: str
                description: Dev rev comments.
            flags:
                type: list
                elements: str
                description:
                    - preview - Generate preview cache only.
                    - auto_lock_ws - Automatically lock and unlock workspace when performing security console task.
                choices: ['none', 'preview', 'auto_lock_ws']
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
'''

EXAMPLES = '''
- name: Commit config to real device
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
    - name: Invoke the task
      fortinet.fortimanager.fmgr_securityconsole_install_device:
        securityconsole_install_device:
          adom: "{{ device_adom }}"
          scope:
            - name: "{{ device_name }}"
              vdom: "{{ device_vdom }}"
      register: installing_task
    - name: Inspect the Task Status
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ installing_task.meta.response_data.task }}"
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
    - name: Run fmgr_securityconsole_install_device
      fortinet.fortimanager.fmgr_securityconsole_install_device:
        bypass_validation: false
        securityconsole_install_device:
          adom: ansible
          dev_rev_comments: ansible-comment
          flags:
            - none
            - preview
            - auto_lock_ws
          scope:
            - name: Ansible-test
              vdom: root
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
        '/securityconsole/install/device'
    ]
    module_arg_spec = {
        'securityconsole_install_device': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'str'},
                'dev_rev_comments': {'type': 'str'},
                'flags': {'type': 'list', 'choices': ['none', 'preview', 'auto_lock_ws'], 'elements': 'str'},
                'scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_install_device'),
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
