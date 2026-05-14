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
module: fmgr_system_sdnproxy
short_description: Configure SDN proxy.
version_added: "2.3.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_sdnproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: SDN proxy name.
                required: true
            password:
                type: list
                elements: str
                description: SDN proxy password.
            server:
                type: str
                description: Server address of the SDN proxy.
            server_port:
                aliases: ['server-port']
                type: int
                description: Port number of the SDN proxy.
            type:
                type: str
                description: Type of SDN proxy.
                choices: ['general', 'fortimanager']
            username:
                type: str
                description: SDN proxy username.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SDN proxy.
      fortinet.fortimanager.fmgr_system_sdnproxy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_sdnproxy:
          name: "your value" # Required variable, string
          # password: <list or string>
          # server: <string>
          # server_port: <integer>
          # type: <value in [general, fortimanager]>
          # username: <string>
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
        '/pm/config/adom/{adom}/obj/system/sdn-proxy',
        '/pm/config/global/obj/system/sdn-proxy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_sdnproxy': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'server': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'server-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'type': {'v_range': [['7.4.1', '']], 'choices': ['general', 'fortimanager'], 'type': 'str'},
                'username': {'v_range': [['7.4.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnproxy'),
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
