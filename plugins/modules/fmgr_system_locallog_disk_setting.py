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
module: fmgr_system_locallog_disk_setting
short_description: Settings for local disk logging.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_locallog_disk_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            diskfull:
                type: str
                description:
                    - Policy to apply when disk is full.
                    - overwrite - Overwrite oldest log when disk is full.
                    - nolog - Stop logging when disk is full.
                choices: ['overwrite', 'nolog']
            log_disk_full_percentage:
                aliases: ['log-disk-full-percentage']
                type: int
                description: Consider log disk as full at this usage percentage.
            max_log_file_size:
                aliases: ['max-log-file-size']
                type: int
                description: Maximum log file size before rolling.
            roll_day:
                aliases: ['roll-day']
                type: list
                elements: str
                description:
                    - Days of week to roll logs.
                    - sunday - Sunday.
                    - monday - Monday.
                    - tuesday - Tuesday.
                    - wednesday - Wednesday.
                    - thursday - Thursday.
                    - friday - Friday.
                    - saturday - Saturday.
                choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                          'saturday']
            roll_schedule:
                aliases: ['roll-schedule']
                type: str
                description:
                    - Frequency to check log file for rolling.
                    - none - Not scheduled.
                    - daily - Every day.
                    - weekly - Every week.
                choices: ['none', 'daily', 'weekly']
            roll_time:
                aliases: ['roll-time']
                type: raw
                description: (list or str) Time to roll logs
            server_type:
                aliases: ['server-type']
                type: str
                description:
                    - Server type.
                    - FTP - Upload via FTP.
                    - SFTP - Upload via SFTP.
                    - SCP - Upload via SCP.
                choices: ['FTP', 'SFTP', 'SCP']
            severity:
                type: str
                description:
                    - Least severity level to log.
                    - emergency - Emergency level.
                    - alert - Alert level.
                    - critical - Critical level.
                    - error - Error level.
                    - warning - Warning level.
                    - notification - Notification level.
                    - information - Information level.
                    - debug - Debug level.
                choices: ['emergency', 'alert', 'critical', 'error', 'warning', 'notification',
                          'information', 'debug']
            status:
                type: str
                description:
                    - Enable/disable local disk log.
                    - disable - Do not log to local disk.
                    - enable - Log to local disk.
                choices: ['disable', 'enable']
            upload:
                type: str
                description:
                    - Upload log file when rolling.
                    - disable - Disable uploading when rolling log file.
                    - enable - Enable uploading when rolling log file.
                choices: ['disable', 'enable']
            upload_delete_files:
                aliases: ['upload-delete-files']
                type: str
                description:
                    - Delete log files after uploading
                    - disable - Do not delete log files after uploading.
                    - enable - Delete log files after uploading.
                choices: ['disable', 'enable']
            upload_time:
                aliases: ['upload-time']
                type: raw
                description: (list or str) Time to upload logs
            uploaddir:
                type: str
                description: Log file upload remote directory.
            uploadip:
                type: str
                description: IP address of log uploading server.
            uploadpass:
                type: raw
                description: (list) Password of user account in upload server.
            uploadport:
                type: int
                description: Server port
            uploadsched:
                type: str
                description:
                    - Scheduled upload
                    - disable - Upload when rolling.
                    - enable - Scheduled upload.
                choices: ['disable', 'enable']
            uploadtype:
                type: list
                elements: str
                description:
                    - Types of log files that need to be uploaded.
                    - event - Upload event log.
                choices: ['event']
            uploaduser:
                type: str
                description: User account in upload server.
            uploadzip:
                type: str
                description:
                    - Compress upload logs.
                    - disable - Upload log files as plain text.
                    - enable - Upload log files compressed.
                choices: ['disable', 'enable']
            log_disk_quota:
                aliases: ['log-disk-quota']
                type: int
                description: Quota for controlling local log size.
            max_log_file_num:
                aliases: ['max-log-file-num']
                type: int
                description: Maximum number of log files before rolling.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Settings for local disk logging.
      fortinet.fortimanager.fmgr_system_locallog_disk_setting:
        # workspace_locking_adom: <global or your adom name>
        system_locallog_disk_setting:
          # diskfull: <value in [overwrite, nolog]>
          # log_disk_full_percentage: <integer>
          # max_log_file_size: <integer>
          # roll_day: ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday",
          #            "saturday"]
          # roll_schedule: <value in [none, daily, weekly]>
          # roll_time: <list or string>
          # server_type: <value in [FTP, SFTP, SCP]>
          # severity: <value in [emergency, alert, critical, ...]>
          # status: <value in [disable, enable]>
          # upload: <value in [disable, enable]>
          # upload_delete_files: <value in [disable, enable]>
          # upload_time: <list or string>
          # uploaddir: <string>
          # uploadip: <string>
          # uploadpass: <list or string>
          # uploadport: <integer>
          # uploadsched: <value in [disable, enable]>
          # uploadtype: ["event"]
          # uploaduser: <string>
          # uploadzip: <value in [disable, enable]>
          # log_disk_quota: <integer>
          # max_log_file_num: <integer>
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
        '/cli/global/system/locallog/disk/setting'
    ]
    module_arg_spec = {
        'system_locallog_disk_setting': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'diskfull': {'choices': ['overwrite', 'nolog'], 'type': 'str'},
                'log-disk-full-percentage': {'type': 'int'},
                'max-log-file-size': {'type': 'int'},
                'roll-day': {'type': 'list', 'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'], 'elements': 'str'},
                'roll-schedule': {'choices': ['none', 'daily', 'weekly'], 'type': 'str'},
                'roll-time': {'type': 'raw'},
                'server-type': {'choices': ['FTP', 'SFTP', 'SCP'], 'type': 'str'},
                'severity': {'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-delete-files': {'choices': ['disable', 'enable'], 'type': 'str'},
                'upload-time': {'type': 'raw'},
                'uploaddir': {'type': 'str'},
                'uploadip': {'type': 'str'},
                'uploadpass': {'no_log': True, 'type': 'raw'},
                'uploadport': {'type': 'int'},
                'uploadsched': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uploadtype': {'type': 'list', 'choices': ['event'], 'elements': 'str'},
                'uploaduser': {'type': 'str'},
                'uploadzip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-disk-quota': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'max-log-file-num': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_locallog_disk_setting'),
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
