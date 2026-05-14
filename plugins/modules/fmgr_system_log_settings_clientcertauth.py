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
module: fmgr_system_log_settings_clientcertauth
short_description: Cli system log settings client cert auth
version_added: "2.13.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_log_settings_clientcertauth:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            mode:
                type: str
                description: Mode.
                choices: ['basic', 'strict']
            tls_port:
                aliases: ['tls-port']
                type: str
                description: Tls port.
                choices: ['both', '514', '6514']
            trusted_client:
                aliases: ['trusted-client']
                type: list
                elements: dict
                description: Trusted client.
                suboptions:
                    certificate:
                        type: list
                        elements: str
                        description: Certificate.
                    description:
                        type: str
                        description: Description.
                    domain:
                        type: str
                        description: Domain.
                    id:
                        type: int
                        description: Id.
                    type:
                        type: str
                        description: Type.
                        choices: ['certificate', 'domain']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Cli system log settings client cert auth
      fortinet.fortimanager.fmgr_system_log_settings_clientcertauth:
        # workspace_locking_adom: <global or your adom name>
        system_log_settings_clientcertauth:
          # mode: <value in [basic, strict]>
          # tls_port: <value in [both, 514, 6514]>
          # trusted_client:
          #   - certificate: <list or string>
          #     description: <string>
          #     domain: <string>
          #     id: <integer>
          #     type: <value in [certificate, domain]>
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
        '/cli/global/system/log/settings/client-cert-auth'
    ]
    module_arg_spec = {
        'system_log_settings_clientcertauth': {
            'type': 'dict', 'v_range': [['7.6.5', '']],
            'options': {
                'mode': {'v_range': [['7.6.5', '']], 'choices': ['basic', 'strict'], 'type': 'str'},
                'tls-port': {'v_range': [['7.6.5', '']], 'choices': ['both', '514', '6514'], 'type': 'str'},
                'trusted-client': {
                    'v_range': [['7.6.5', '']],
                    'type': 'list',
                    'options': {
                        'certificate': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                        'description': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'domain': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'type': {'v_range': [['7.6.5', '']], 'choices': ['certificate', 'domain'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_settings_clientcertauth'),
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
