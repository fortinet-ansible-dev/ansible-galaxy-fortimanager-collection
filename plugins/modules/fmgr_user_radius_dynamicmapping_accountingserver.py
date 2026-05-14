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
module: fmgr_user_radius_dynamicmapping_accountingserver
short_description: Additional accounting servers.
version_added: "2.1.0"
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
    radius:
        description: The parameter (radius) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    user_radius_dynamicmapping_accountingserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Id.
                required: true
            interface:
                type: str
                description: Interface.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Interface select method.
                choices: ['auto', 'sdwan', 'specify']
            port:
                type: int
                description: Port.
            secret:
                type: raw
                description: (list) Secret.
            server:
                type: str
                description: Server.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source ip.
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
    - name: Additional accounting servers.
      fortinet.fortimanager.fmgr_user_radius_dynamicmapping_accountingserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        radius: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        user_radius_dynamicmapping_accountingserver:
          id: 0 # Required variable, integer
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # port: <integer>
          # secret: <list or string>
          # server: <string>
          # source_ip: <string>
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
        '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server',
        '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'radius': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_radius_dynamicmapping_accountingserver': {
            'type': 'dict', 'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'id': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'required': True, 'type': 'int'},
                'interface': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'interface-select-method': {
                    'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'port': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'secret': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'no_log': True, 'type': 'raw'},
                'server': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'source-ip': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'status': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_radius_dynamicmapping_accountingserver'),
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
