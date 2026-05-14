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
module: fmgr_system_backup_allsettings
short_description: Scheduled backup settings.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_backup_allsettings:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cert:
                type: str
                description: SSH certificate for authentication.
            crptpasswd:
                type: raw
                description: (list) Optional password to protect backup content.
            directory:
                type: str
                description: Directory in which file will be stored on backup server.
            passwd:
                type: raw
                description: (list) Backup server login user password.
            protocol:
                type: str
                description:
                    - Protocol used to backup.
                    - sftp - SFTP.
                    - ftp - FTP.
                    - scp - SCP.
                choices: ['sftp', 'ftp', 'scp']
            server:
                type: str
                description: Backup server name/IP.
            status:
                type: str
                description:
                    - Enable/disable schedule backup.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            time:
                type: str
                description: Time to backup.
            user:
                type: str
                description: Backup server login user.
            week_days:
                type: list
                elements: str
                description:
                    - Week days to backup.
                    - monday - Monday.
                    - tuesday - Tuesday.
                    - wednesday - Wednesday.
                    - thursday - Thursday.
                    - friday - Friday.
                    - saturday - Saturday.
                    - sunday - Sunday.
                choices: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
                          'sunday']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Scheduled backup settings.
      fortinet.fortimanager.fmgr_system_backup_allsettings:
        # workspace_locking_adom: <global or your adom name>
        system_backup_allsettings:
          # cert: <string>
          # crptpasswd: <list or string>
          # directory: <string>
          # passwd: <list or string>
          # protocol: <value in [sftp, ftp, scp]>
          # server: <string>
          # status: <value in [disable, enable]>
          # time: <string>
          # user: <string>
          # week_days: ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
          #             "sunday"]
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
        '/cli/global/system/backup/all-settings'
    ]
    module_arg_spec = {
        'system_backup_allsettings': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'cert': {'type': 'str'},
                'crptpasswd': {'no_log': True, 'type': 'raw'},
                'directory': {'type': 'str'},
                'passwd': {'no_log': True, 'type': 'raw'},
                'protocol': {'choices': ['sftp', 'ftp', 'scp'], 'type': 'str'},
                'server': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'time': {'type': 'str'},
                'user': {'type': 'str'},
                'week_days': {
                    'type': 'list',
                    'choices': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_backup_allsettings'),
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
