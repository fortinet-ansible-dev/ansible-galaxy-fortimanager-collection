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
module: fmgr_application_internetservicecustom_entry
short_description: Entries added to the Internet service database and custom database.
version_added: "2.2.0"
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
    internet-service-custom:
        description: Deprecated, please use "internet_service_custom"
        type: str
    internet_service_custom:
        description: The parameter (internet-service-custom) in requested url.
        type: str
    application_internetservicecustom_entry:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dst:
                type: str
                description: Destination address name.
            id:
                type: int
                description: Entry ID
                required: true
            port_range:
                aliases: ['port-range']
                type: list
                elements: dict
                description: Port range.
                suboptions:
                    end_port:
                        aliases: ['end-port']
                        type: int
                        description: End destination port number
                    id:
                        type: int
                        description: Custom entry port range ID.
                    start_port:
                        aliases: ['start-port']
                        type: int
                        description: Start destination port number
            protocol:
                type: int
                description: Protocol number.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Entries added to the Internet service database and custom database.
      fortinet.fortimanager.fmgr_application_internetservicecustom_entry:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        internet_service_custom: <your own value>
        state: present # <value in [present, absent]>
        application_internetservicecustom_entry:
          id: 0 # Required variable, integer
          # dst: <string>
          # port_range:
          #   - end_port: <integer>
          #     id: <integer>
          #     start_port: <integer>
          # protocol: <integer>
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
        '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry',
        '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'internet-service-custom': {'type': 'str', 'api_name': 'internet_service_custom'},
        'internet_service_custom': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'application_internetservicecustom_entry': {
            'type': 'dict', 'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'dst': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'id': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'int'},
                'port-range': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'end-port': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'start-port': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'protocol': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_internetservicecustom_entry'),
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
