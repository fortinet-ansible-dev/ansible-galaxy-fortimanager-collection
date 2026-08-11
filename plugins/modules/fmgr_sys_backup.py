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
module: fmgr_sys_backup
short_description: Backup FortiManager configuration.
version_added: "2.15.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
options:
  sys_backup:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      filename:
        type: str
        description: Destination path and file name on remote server.
      passwd:
        type: list
        elements: str
        description: Password for password-protected configuration backup file.
      port:
        type: int
        description: Remote server port.
      server:
        type: str
        description: Remote server address.
      service:
        type: str
        description: Protocol to backup configuration.
        choices: ['ftp', 'scp', 'sftp', 'tftp']
      username:
        type: str
        description: User name to log in to the remote server.
      userpasswd:
        type: list
        elements: str
        description: Password to log in to the remote server.
'''

EXAMPLES = '''
- name: Test FortiManager configuration backup
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Back up the FortiManager configuration
      fortinet.fortimanager.fmgr_sys_backup:
        enable_log: true
        bypass_validation: true
        sys_backup:
          filename: test_backup.dat
          passwd: test_backup_password
          server: 192.0.2.1
          service: tftp
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
        '/sys/backup'
    ]
    module_arg_spec = {
        'sys_backup': {
            'type': 'dict', 'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']],
            'options': {
                'filename': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'type': 'str'},
                'passwd': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'type': 'int'},
                'server': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'type': 'str'},
                'service': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'choices': ['ftp', 'scp', 'sftp', 'tftp'], 'type': 'str'},
                'username': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'type': 'str'},
                'userpasswd': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'sys_backup'),
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
