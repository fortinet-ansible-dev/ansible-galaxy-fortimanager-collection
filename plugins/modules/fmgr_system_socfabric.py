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
module: fmgr_system_socfabric
short_description: SOC Fabric.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_socfabric:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: Fabric name.
            port:
                type: int
                description: Communication port
            psk:
                type: raw
                description: (list) Fabric auth pwd.
            role:
                type: str
                description:
                    - Enable or Disable SOC Fabric.
                    - member - SOC Fabric member.
                    - supervisor - SOC Fabric supervisor.
                choices: ['member', 'supervisor']
            secure_connection:
                aliases: ['secure-connection']
                type: str
                description:
                    - Enable or Disable SSL/TLS.
                    - disable - Disable SSL/TLS.
                    - enable - Enable SSL/TLS.
                choices: ['disable', 'enable']
            status:
                type: str
                description:
                    - Enable or Disable SOC Fabric.
                    - disable - Disable SOC Fabric.
                    - enable - Enable SOC Fabric.
                choices: ['disable', 'enable']
            supervisor:
                type: str
                description: IP/FQDN of supervisor.
            trusted_list:
                aliases: ['trusted-list']
                type: list
                elements: dict
                description: Trusted list.
                suboptions:
                    id:
                        type: int
                        description: Trusted list ID.
                    serial:
                        type: str
                        description: FAZ serial number
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SOC Fabric.
      fortinet.fortimanager.fmgr_system_socfabric:
        # workspace_locking_adom: <global or your adom name>
        system_socfabric:
          # name: <string>
          # port: <integer>
          # psk: <list or string>
          # role: <value in [member, supervisor]>
          # secure_connection: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # supervisor: <string>
          # trusted_list:
          #   - id: <integer>
          #     serial: <string>
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
        '/cli/global/system/soc-fabric'
    ]
    module_arg_spec = {
        'system_socfabric': {
            'type': 'dict', 'v_range': [['7.0.0', '']],
            'options': {
                'name': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'psk': {'v_range': [['7.0.0', '7.2.12']], 'type': 'raw'},
                'role': {'v_range': [['7.0.0', '']], 'choices': ['member', 'supervisor'], 'type': 'str'},
                'secure-connection': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'supervisor': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'trusted-list': {
                    'v_range': [['7.4.0', '']],
                    'type': 'list',
                    'options': {'id': {'v_range': [['7.4.0', '']], 'type': 'int'}, 'serial': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_socfabric'),
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
