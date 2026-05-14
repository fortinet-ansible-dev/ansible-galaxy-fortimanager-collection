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
module: fmgr_system_snmp_user
short_description: SNMP user configuration.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_snmp_user:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_proto:
                aliases: ['auth-proto']
                type: str
                description:
                    - Authentication protocol.
                    - md5 - HMAC-MD5-96 authentication protocol.
                    - sha - HMAC-SHA-96 authentication protocol.
                choices: ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512']
            auth_pwd:
                aliases: ['auth-pwd']
                type: raw
                description: (list) Password for authentication protocol.
            events:
                type: list
                elements: str
                description:
                    - SNMP notifications
                    - disk_low - Disk usage too high.
                    - ha_switch - HA switch.
                    - intf_ip_chg - Interface IP address changed.
                    - sys_reboot - System reboot.
                    - cpu_high - CPU usage too high.
                    - mem_low - Available memory is low.
                    - log-alert - Log base alert message.
                    - log-rate - High incoming log rate detected.
                    - log-data-rate - High incoming log data rate detected.
                    - lic-gbday - High licensed log GB/day detected.
                    - lic-dev-quota - High licensed device quota detected.
                    - cpu-high-exclude-nice - CPU usage exclude NICE threshold.
                choices: ['disk_low', 'ha_switch', 'intf_ip_chg', 'sys_reboot', 'cpu_high',
                          'mem_low', 'log-alert', 'log-rate', 'log-data-rate', 'lic-gbday',
                          'lic-dev-quota', 'cpu-high-exclude-nice']
            name:
                type: str
                description: SNMP user name.
                required: true
            notify_hosts:
                aliases: ['notify-hosts']
                type: str
                description: Hosts to send notifications
            notify_hosts6:
                aliases: ['notify-hosts6']
                type: str
                description: IPv6 hosts to send notifications
            priv_proto:
                aliases: ['priv-proto']
                type: str
                description:
                    - Privacy
                    - aes - CFB128-AES-128 symmetric encryption protocol.
                    - des - CBC-DES symmetric encryption protocol.
                choices: ['aes', 'des', 'aes256', 'aes256cisco']
            priv_pwd:
                aliases: ['priv-pwd']
                type: raw
                description: (list) Password for privacy
            queries:
                type: str
                description:
                    - Enable/disable queries for this user.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_port:
                aliases: ['query-port']
                type: int
                description: SNMPv3 query port.
            security_level:
                aliases: ['security-level']
                type: str
                description:
                    - Security level for message authentication and encryption.
                    - no-auth-no-priv - Message with no authentication and no privacy
                    - auth-no-priv - Message with authentication but no privacy
                    - auth-priv - Message with authentication and privacy
                choices: ['no-auth-no-priv', 'auth-no-priv', 'auth-priv']
            notify_port:
                aliases: ['notify-port']
                type: int
                description: Notify port.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: SNMP user configuration.
      fortinet.fortimanager.fmgr_system_snmp_user:
        bypass_validation: false
        state: present
        system_snmp_user:
          auth_proto: md5 # <value in [md5, sha]>
          auth_pwd: fortinet
          events:
            - disk_low
            - ha_switch
            - intf_ip_chg
            - sys_reboot
            - cpu_high
            - mem_low
            - log-alert
            - log-rate
            - log-data-rate
            - lic-gbday
            - lic-dev-quota
            - cpu-high-exclude-nice
          name: ansible-test-snmpuser
          queries: disable
          security_level: no-auth-no-priv # <value in [no-auth-no-priv, auth-no-priv, auth-priv]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the SNMP users
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_snmp_user"
          params:
            user: "your_value"
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
        '/cli/global/system/snmp/user'
    ]
    module_arg_spec = {
        'system_snmp_user': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-proto': {'choices': ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'], 'type': 'str'},
                'auth-pwd': {'type': 'raw'},
                'events': {
                    'type': 'list',
                    'choices': [
                        'disk_low', 'ha_switch', 'intf_ip_chg', 'sys_reboot', 'cpu_high', 'mem_low', 'log-alert', 'log-rate', 'log-data-rate',
                        'lic-gbday', 'lic-dev-quota', 'cpu-high-exclude-nice'
                    ],
                    'elements': 'str'
                },
                'name': {'required': True, 'type': 'str'},
                'notify-hosts': {'type': 'str'},
                'notify-hosts6': {'type': 'str'},
                'priv-proto': {'choices': ['aes', 'des', 'aes256', 'aes256cisco'], 'type': 'str'},
                'priv-pwd': {'type': 'raw'},
                'queries': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-port': {'type': 'int'},
                'security-level': {'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'], 'type': 'str'},
                'notify-port': {'v_range': [['7.2.10', '7.2.12'], ['7.4.6', '7.4.10'], ['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_snmp_user'),
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
