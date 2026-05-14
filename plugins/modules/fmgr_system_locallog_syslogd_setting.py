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
module: fmgr_system_locallog_syslogd_setting
short_description: Settings for remote syslog server.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_locallog_syslogd_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            csv:
                type: str
                description:
                    - CSV format.
                    - disable - Disable CSV format.
                    - enable - Enable CSV format.
                choices: ['disable', 'enable']
            facility:
                type: str
                description:
                    - Remote syslog facility.
                    - kernel - Kernel messages.
                    - user - Random user-level messages.
                    - ntp - NTP daemon.
                    - audit - Log audit.
                    - alert - Log alert.
                    - clock - Clock daemon.
                    - mail - Mail system.
                    - daemon - System daemons.
                    - auth - Security/authorization messages.
                    - syslog - Messages generated internally by syslog daemon.
                    - lpr - Line printer subsystem.
                    - news - Network news subsystem.
                    - uucp - Network news subsystem.
                    - cron - Clock daemon.
                    - authpriv - Security/authorization messages
                    - ftp - FTP daemon.
                    - local0 - Reserved for local use.
                    - local1 - Reserved for local use.
                    - local2 - Reserved for local use.
                    - local3 - Reserved for local use.
                    - local4 - Reserved for local use.
                    - local5 - Reserved for local use.
                    - local6 - Reserved for local use.
                    - local7 - Reserved for local use.
                choices: ['kernel', 'user', 'ntp', 'audit', 'alert', 'clock', 'mail', 'daemon',
                          'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
                          'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6',
                          'local7']
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
                    - Remote syslog log.
                    - disable - Do not log to remote syslog server.
                    - enable - Log to remote syslog server.
                choices: ['disable', 'enable']
            syslog_name:
                aliases: ['syslog-name']
                type: str
                description: Remote syslog server name.
            cert:
                type: str
                description: Select local certificate used for secure connection.
            reliable:
                type: str
                description:
                    - Enable/disable reliable realtime logging.
                    - disable - Disable reliable realtime logging.
                    - enable - Enable reliable realtime logging.
                choices: ['disable', 'enable']
            secure_connection:
                aliases: ['secure-connection']
                type: str
                description:
                    - Enable/disable connection secured by TLS/SSL.
                    - disable - Disable SSL connection.
                    - enable - Enable SSL connection.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Settings for remote syslog server.
      fortinet.fortimanager.fmgr_system_locallog_syslogd_setting:
        # workspace_locking_adom: <global or your adom name>
        system_locallog_syslogd_setting:
          # csv: <value in [disable, enable]>
          # facility: <value in [kernel, user, ntp, ...]>
          # severity: <value in [emergency, alert, critical, ...]>
          # status: <value in [disable, enable]>
          # syslog_name: <string>
          # cert: <string>
          # reliable: <value in [disable, enable]>
          # secure_connection: <value in [disable, enable]>
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
        '/cli/global/system/locallog/syslogd/setting'
    ]
    module_arg_spec = {
        'system_locallog_syslogd_setting': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'csv': {'choices': ['disable', 'enable'], 'type': 'str'},
                'facility': {
                    'choices': [
                        'kernel', 'user', 'ntp', 'audit', 'alert', 'clock', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron',
                        'authpriv', 'ftp', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                    ],
                    'type': 'str'
                },
                'severity': {'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'syslog-name': {'type': 'str'},
                'cert': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.4.2']], 'type': 'str'},
                'reliable': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.4.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secure-connection': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.4.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_locallog_syslogd_setting'),
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
