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
module: fmgr_system_admin_tacacs
short_description: TACACS+ server entry configuration.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_admin_tacacs:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authen_type:
                aliases: ['authen-type']
                type: str
                description:
                    - Authentication type.
                    - auto - Use PAP, MSCHAP, and CHAP
                    - ascii - ASCII.
                    - pap - PAP.
                    - chap - CHAP.
                    - mschap - MSCHAP.
                choices: ['auto', 'ascii', 'pap', 'chap', 'mschap']
            authorization:
                type: str
                description:
                    - Enable/disable TACACS+ authorization.
                    - disable - Disable TACACS+ authorization.
                    - enable - Enable TACACS+ authorization
                choices: ['disable', 'enable']
            key:
                type: raw
                description: (list) No description
            name:
                type: str
                description: TACACS+ server entry name.
                required: true
            port:
                type: int
                description: Port number of TACACS+ server.
            secondary_key:
                aliases: ['secondary-key']
                type: raw
                description: (list) No description
            secondary_server:
                aliases: ['secondary-server']
                type: str
                description: No description
            server:
                type: str
                description: No description
            tertiary_key:
                aliases: ['tertiary-key']
                type: raw
                description: (list) No description
            tertiary_server:
                aliases: ['tertiary-server']
                type: str
                description: No description
            src_ip:
                aliases: ['src-ip']
                type: str
                description: Src ip.
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
    - name: TACACS+ server entry configuration.
      fortinet.fortimanager.fmgr_system_admin_tacacs:
        bypass_validation: false
        state: present
        system_admin_tacacs:
          authen_type: auto # <value in [auto, ascii, pap, ...]>
          authorization: disable
          key: fortinet
          name: ansible-test-tacacs
          port: 1
          server: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the TACACS+ servers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_tacacs"
          params:
            tacacs: "your_value"
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
        '/cli/global/system/admin/tacacs'
    ]
    module_arg_spec = {
        'system_admin_tacacs': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'authen-type': {'choices': ['auto', 'ascii', 'pap', 'chap', 'mschap'], 'type': 'str'},
                'authorization': {'choices': ['disable', 'enable'], 'type': 'str'},
                'key': {'no_log': True, 'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'port': {'type': 'int'},
                'secondary-key': {'no_log': True, 'type': 'raw'},
                'secondary-server': {'type': 'str'},
                'server': {'type': 'str'},
                'tertiary-key': {'no_log': True, 'type': 'raw'},
                'tertiary-server': {'type': 'str'},
                'src-ip': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_tacacs'),
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
