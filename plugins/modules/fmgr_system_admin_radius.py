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
module: fmgr_system_admin_radius
short_description: Configure radius.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_admin_radius:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_type:
                aliases: ['auth-type']
                type: str
                description:
                    - Authentication protocol.
                    - any - Use any supported authentication protocol.
                    - pap - PAP.
                    - chap - CHAP.
                    - mschap2 - MSCHAPv2.
                choices: ['any', 'pap', 'chap', 'mschap2']
            name:
                type: str
                description: Name.
                required: true
            nas_ip:
                aliases: ['nas-ip']
                type: str
                description: NAS IP address and called station ID.
            port:
                type: int
                description: Server port.
            secondary_secret:
                aliases: ['secondary-secret']
                type: raw
                description: (list) Secondary server secret.
            secondary_server:
                aliases: ['secondary-server']
                type: str
                description: Secondary server name/IP.
            secret:
                type: raw
                description: (list) Server secret.
            server:
                type: str
                description: Server name/IP.
            ca_cert:
                aliases: ['ca-cert']
                type: str
                description: Ca cert.
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Client cert.
            message_authenticator:
                aliases: ['message-authenticator']
                type: str
                description: Message authenticator.
                choices: ['optional', 'require']
            protocol:
                type: str
                description: Protocol.
                choices: ['udp', 'tls']
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
    - name: Configure radius.
      fortinet.fortimanager.fmgr_system_admin_radius:
        bypass_validation: false
        state: present
        system_admin_radius:
          auth_type: pap # <value in [any, pap, chap, ...]>
          name: ansible-test-radius
          port: 1812
          server: "ALL"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the radius
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_radius"
          params:
            radius: "your_value"
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
        '/cli/global/system/admin/radius'
    ]
    module_arg_spec = {
        'system_admin_radius': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-type': {'choices': ['any', 'pap', 'chap', 'mschap2'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'nas-ip': {'type': 'str'},
                'port': {'type': 'int'},
                'secondary-secret': {'no_log': True, 'type': 'raw'},
                'secondary-server': {'type': 'str'},
                'secret': {'no_log': True, 'type': 'raw'},
                'server': {'type': 'str'},
                'ca-cert': {'v_range': [['7.2.10', '7.2.12'], ['7.4.6', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.2.10', '7.2.12'], ['7.4.6', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'message-authenticator': {
                    'v_range': [['7.2.10', '7.2.12'], ['7.4.6', '7.4.10'], ['7.6.2', '']],
                    'choices': ['optional', 'require'],
                    'type': 'str'
                },
                'protocol': {'v_range': [['7.2.10', '7.2.12'], ['7.4.6', '7.4.10'], ['7.6.2', '']], 'choices': ['udp', 'tls'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_radius'),
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
