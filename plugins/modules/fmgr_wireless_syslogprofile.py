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
module: fmgr_wireless_syslogprofile
short_description: Configure Wireless Termination Points
version_added: "2.2.0"
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
    wireless_syslogprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            log_level:
                aliases: ['log-level']
                type: str
                description: Lowest level of log messages that FortiAP units send to this server
                choices: ['emergency', 'alert', 'critical', 'error', 'warning', 'notification',
                          'information', 'debugging']
            name:
                type: str
                description: WTP system log server profile name.
                required: true
            server_addr_type:
                aliases: ['server-addr-type']
                type: str
                description: Syslog server address type
                choices: ['fqdn', 'ip']
            server_fqdn:
                aliases: ['server-fqdn']
                type: str
                description: FQDN of syslog server that FortiAP units send log messages to.
            server_ip:
                aliases: ['server-ip']
                type: str
                description: IP address of syslog server that FortiAP units send log messages to.
            server_port:
                aliases: ['server-port']
                type: int
                description: Port number of syslog server that FortiAP units send log messages to
            server_status:
                aliases: ['server-status']
                type: str
                description: Enable/disable FortiAP units to send log messages to a syslog server
                choices: ['disable', 'enable']
            server_type:
                aliases: ['server-type']
                type: str
                description: Configure syslog server type
                choices: ['standard', 'fortianalyzer']
            server:
                type: str
                description: Syslog server CN domain name or IP address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Wireless Termination Points
      fortinet.fortimanager.fmgr_wireless_syslogprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        wireless_syslogprofile:
          name: "your value" # Required variable, string
          # comment: <string>
          # log_level: <value in [emergency, alert, critical, ...]>
          # server_addr_type: <value in [fqdn, ip]>
          # server_fqdn: <string>
          # server_ip: <string>
          # server_port: <integer>
          # server_status: <value in [disable, enable]>
          # server_type: <value in [standard, fortianalyzer]>
          # server: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile',
        '/pm/config/global/obj/wireless-controller/syslog-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wireless_syslogprofile': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'comment': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'log-level': {
                    'v_range': [['7.2.1', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debugging'],
                    'type': 'str'
                },
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'server-addr-type': {'v_range': [['7.2.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'server-fqdn': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'server-ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'server-port': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'server-status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-type': {'v_range': [['7.6.2', '']], 'choices': ['standard', 'fortianalyzer'], 'type': 'str'},
                'server': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_syslogprofile'),
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
