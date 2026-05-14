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
module: fmgr_fmupdate_fgdsetting_serveroverride
short_description: Cli fmupdate fgd setting server override
version_added: "2.10.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_fgdsetting_serveroverride:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            servlist:
                type: list
                elements: dict
                description: Servlist.
                suboptions:
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: Ip.
                    ip6:
                        type: str
                        description: Ip6.
                    port:
                        type: int
                        description: Port.
                    service_type:
                        aliases: ['service-type']
                        type: str
                        description: Service type.
                        choices: ['fgd', 'fsa', 'fgfq', 'geoip', 'iot-collect']
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Cli fmupdate fgd setting server override
      fortinet.fortimanager.fmgr_fmupdate_fgdsetting_serveroverride:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_fgdsetting_serveroverride:
          # servlist:
          #   - id: <integer>
          #     ip: <string>
          #     ip6: <string>
          #     port: <integer>
          #     service_type: <value in [fgd, fsa, fgfq, ...]>
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
        '/cli/global/fmupdate/fgd-setting/server-override'
    ]
    module_arg_spec = {
        'fmupdate_fgdsetting_serveroverride': {
            'type': 'dict', 'v_range': [['7.6.3', '']],
            'options': {
                'servlist': {
                    'v_range': [['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.6.3', '']], 'type': 'str'},
                        'ip6': {'v_range': [['7.6.3', '']], 'type': 'str'},
                        'port': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'service-type': {'v_range': [['7.6.3', '']], 'choices': ['fgd', 'fsa', 'fgfq', 'geoip', 'iot-collect'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fgdsetting_serveroverride'),
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
