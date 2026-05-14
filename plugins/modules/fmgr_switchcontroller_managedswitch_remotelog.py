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
module: fmgr_switchcontroller_managedswitch_remotelog
short_description: Configure logging by FortiSwitch device to a remote syslog server.
version_added: "2.1.0"
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
    managed-switch:
        description: Deprecated, please use "managed_switch"
        type: str
    managed_switch:
        description: The parameter (managed-switch) in requested url.
        type: str
    switchcontroller_managedswitch_remotelog:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            csv:
                type: str
                description: Enable/disable comma-separated value
                choices: ['disable', 'enable']
            facility:
                type: str
                description: Facility to log to remote syslog server.
                choices: ['kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
                          'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
                          'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6',
                          'local7']
            name:
                type: str
                description: Remote log name.
                required: true
            port:
                type: int
                description: Remote syslog server listening port.
            server:
                type: str
                description: IPv4 address of the remote syslog server.
            severity:
                type: str
                description: Severity of logs to be transferred to remote log server.
                choices: ['emergency', 'alert', 'critical', 'error', 'warning', 'notification',
                          'information', 'debug']
            status:
                type: str
                description: Enable/disable logging by FortiSwitch device to a remote syslog server.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure logging by FortiSwitch device to a remote syslog server.
      fortinet.fortimanager.fmgr_switchcontroller_managedswitch_remotelog:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        managed_switch: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_remotelog:
          name: "your value" # Required variable, string
          # csv: <value in [disable, enable]>
          # facility: <value in [kernel, user, mail, ...]>
          # port: <integer>
          # server: <string>
          # severity: <value in [emergency, alert, critical, ...]>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_managedswitch_remotelog': {
            'type': 'dict', 'v_range': [['6.2.1', '6.2.3']],
            'options': {
                'csv': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'facility': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'choices': [
                        'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert',
                        'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                    ],
                    'type': 'str'
                },
                'name': {'v_range': [['6.2.1', '6.2.3']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                'server': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'},
                'severity': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_remotelog'),
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
