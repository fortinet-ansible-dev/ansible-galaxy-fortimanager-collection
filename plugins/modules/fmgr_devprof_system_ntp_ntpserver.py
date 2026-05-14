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
module: fmgr_devprof_system_ntp_ntpserver
short_description: Configure the FortiGate to connect to any available third-party NTP server.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_ntp_ntpserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authentication:
                type: str
                description: Enable/disable MD5 authentication.
                choices: ['disable', 'enable']
            id:
                type: int
                description: NTP server ID.
                required: true
            key:
                type: raw
                description: (list) Key for MD5 authentication.
            key_id:
                aliases: ['key-id']
                type: int
                description: Key ID for authentication.
            ntpv3:
                type: str
                description: Enable to use NTPv3 instead of NTPv4.
                choices: ['disable', 'enable']
            server:
                type: str
                description: IP address or hostname of the NTP Server.
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            ip_type:
                aliases: ['ip-type']
                type: str
                description: Choose to connect to IPv4 or/and IPv6 NTP server.
                choices: ['IPv6', 'IPv4', 'Both']
            key_type:
                aliases: ['key-type']
                type: str
                description: Select NTP authentication type.
                choices: ['SHA1', 'SHA256', 'MD5']
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure the FortiGate to connect to any available third-party NTP server.
      fortinet.fortimanager.fmgr_devprof_system_ntp_ntpserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        state: present # <value in [present, absent]>
        devprof_system_ntp_ntpserver:
          id: 0 # Required variable, integer
          # authentication: <value in [disable, enable]>
          # key: <list or string>
          # key_id: <integer>
          # ntpv3: <value in [disable, enable]>
          # server: <string>
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ip_type: <value in [IPv6, IPv4, Both]>
          # key_type: <value in [SHA1, SHA256, MD5]>
          # vrf_select: <integer>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_ntp_ntpserver': {
            'type': 'dict', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'authentication': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'required': True, 'type': 'int'},
                'key': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'no_log': True, 'type': 'raw'},
                'key-id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'no_log': True, 'type': 'int'},
                'ntpv3': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.0.2'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface-select-method': {
                    'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.0.2'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'ip-type': {'v_range': [['7.4.2', '']], 'choices': ['IPv6', 'IPv4', 'Both'], 'type': 'str'},
                'key-type': {'v_range': [['7.4.3', '']], 'choices': ['SHA1', 'SHA256', 'MD5'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_ntp_ntpserver'),
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
