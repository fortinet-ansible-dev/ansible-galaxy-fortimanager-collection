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
module: fmgr_fmupdate_fdssetting_serveroverride
short_description: Server override configure.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_fdssetting_serveroverride:
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
                        description: Override server ID
                    ip:
                        type: str
                        description: IPv4 address of the override server.
                    ip6:
                        type: str
                        description: IPv6 address of the override server.
                    port:
                        type: int
                        description: Port number to use when contacting FortiGuard
                    service_type:
                        aliases: ['service-type']
                        type: raw
                        description:
                            - (list or str)
                            - Override service type.
                            - fds - Server override config for fds
                            - fct - Server override config for fct
                        choices: ['fds', 'fct', 'fai']
            status:
                type: str
                description:
                    - Override status.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Server override configure.
      fortinet.fortimanager.fmgr_fmupdate_fdssetting_serveroverride:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_fdssetting_serveroverride:
          # servlist:
          #   - id: <integer>
          #     ip: <string>
          #     ip6: <string>
          #     port: <integer>
          #     service_type: ["fds", "fct", "fai"]
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
        '/cli/global/fmupdate/fds-setting/server-override'
    ]
    module_arg_spec = {
        'fmupdate_fdssetting_serveroverride': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'servlist': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'ip6': {'type': 'str'},
                        'port': {'type': 'int'},
                        'service-type': {'type': 'raw', 'choices': ['fds', 'fct', 'fai']}
                    },
                    'elements': 'dict'
                },
                'status': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fdssetting_serveroverride'),
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
