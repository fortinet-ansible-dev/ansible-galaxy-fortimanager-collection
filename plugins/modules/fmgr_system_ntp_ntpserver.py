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
module: fmgr_system_ntp_ntpserver
short_description: NTP server.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_ntp_ntpserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authentication:
                type: str
                description:
                    - Enable/disable MD5 authentication.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            id:
                type: int
                description: Time server ID.
                required: true
            key:
                type: raw
                description: (list) Key for authentication.
            key_id:
                aliases: ['key-id']
                type: int
                description: Key ID for authentication.
            ntpv3:
                type: str
                description:
                    - Enable/disable NTPv3.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            server:
                type: str
                description: IP address/hostname of NTP Server.
            maxpoll:
                type: int
                description: Maximum poll interval in seconds as power of 2
            minpoll:
                type: int
                description: Minimum poll interval in seconds as power of 2
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
    - name: NTP server.
      fortinet.fortimanager.fmgr_system_ntp_ntpserver:
        bypass_validation: false
        state: present
        system_ntp_ntpserver:
          authentication: disable
          id: 1
          key: fortinet
          key_id: 1
          ntpv3: enable
          server: ntp1.fortinet.net

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the NTP servers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_ntp_ntpserver"
          params:
            ntpserver: "your_value"
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
        '/cli/global/system/ntp/ntpserver'
    ]
    module_arg_spec = {
        'system_ntp_ntpserver': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'key': {'no_log': True, 'type': 'raw'},
                'key-id': {'no_log': True, 'type': 'int'},
                'ntpv3': {'choices': ['disable', 'enable'], 'type': 'str'},
                'server': {'type': 'str'},
                'maxpoll': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'minpoll': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ntp_ntpserver'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
