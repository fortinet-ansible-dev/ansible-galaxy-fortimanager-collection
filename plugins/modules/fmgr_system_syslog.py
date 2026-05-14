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
module: fmgr_system_syslog
short_description: Syslog servers.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_syslog:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ip:
                type: str
                description: Syslog server IP address or hostname.
            name:
                type: str
                description: Syslog server name.
                required: true
            port:
                type: int
                description: Syslog server port.
            local_cert:
                aliases: ['local-cert']
                type: str
                description: Select local certificate used for secure connection.
            peer_cert_cn:
                aliases: ['peer-cert-cn']
                type: str
                description: Certificate common name of syslog server.
            reliable:
                type: str
                description:
                    - Enable/disable reliable connection with syslog server.
                    - disable - Disable reliable connection with syslog server.
                    - enable - Enable reliable connection with syslog server.
                choices: ['disable', 'enable']
            secure_connection:
                aliases: ['secure-connection']
                type: str
                description:
                    - Enable/disable connection secured by TLS/SSL.
                    - disable - Disable SSL connection.
                    - enable - Enable SSL connection.
                choices: ['disable', 'enable']
            ssl_protocol:
                aliases: ['ssl-protocol']
                type: str
                description:
                    - set the lowest SSL protocol version for connection to syslog server.
                    - follow-global-ssl-protocol - Follow system.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices: ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2',
                          'tlsv1.3']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Syslog servers.
      fortinet.fortimanager.fmgr_system_syslog:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_syslog:
          name: "your value" # Required variable, string
          # ip: <string>
          # port: <integer>
          # local_cert: <string>
          # peer_cert_cn: <string>
          # reliable: <value in [disable, enable]>
          # secure_connection: <value in [disable, enable]>
          # ssl_protocol: <value in [follow-global-ssl-protocol, sslv3, tlsv1.0, ...]>
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
        '/cli/global/system/syslog'
    ]
    module_arg_spec = {
        'system_syslog': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'ip': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'port': {'type': 'int'},
                'local-cert': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'type': 'str'},
                'peer-cert-cn': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'type': 'str'},
                'reliable': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secure-connection': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-protocol': {
                    'v_range': [['7.4.4', '7.4.10'], ['7.6.2', '']],
                    'choices': ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_syslog'),
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
