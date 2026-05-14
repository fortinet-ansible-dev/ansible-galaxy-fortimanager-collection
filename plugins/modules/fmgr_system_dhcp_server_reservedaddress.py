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
module: fmgr_system_dhcp_server_reservedaddress
short_description: Options for the DHCP server to assign IP settings to specific MAC addresses.
version_added: "2.0.0"
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
    server:
        description: The parameter (server) in requested url.
        type: str
        required: true
    system_dhcp_server_reservedaddress:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Options for the DHCP server to configure the client with the reserved MAC address.
                choices: ['assign', 'block', 'reserved']
            description:
                type: str
                description: Description.
            id:
                type: int
                description: ID.
                required: true
            ip:
                type: str
                description: IP address to be reserved for the MAC address.
            mac:
                type: str
                description: MAC address of the client that will get the reserved IP address.
            circuit_id:
                aliases: ['circuit-id']
                type: str
                description: Option 82 circuit-ID of the client that will get the reserved IP address.
            circuit_id_type:
                aliases: ['circuit-id-type']
                type: str
                description: DHCP option type.
                choices: ['hex', 'string']
            remote_id:
                aliases: ['remote-id']
                type: str
                description: Option 82 remote-ID of the client that will get the reserved IP address.
            remote_id_type:
                aliases: ['remote-id-type']
                type: str
                description: DHCP option type.
                choices: ['hex', 'string']
            type:
                type: str
                description: DHCP reserved-address type.
                choices: ['mac', 'option82']
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
    - name: Options for the DHCP server to assign IP settings to specific MAC addresses.
      fortinet.fortimanager.fmgr_system_dhcp_server_reservedaddress:
        bypass_validation: false
        adom: ansible
        server: 1 # id
        state: present
        system_dhcp_server_reservedaddress:
          action: assign # <value in [assign, block, reserved]>
          description: ansible-description
          id: 1
          ip: 222.222.222.1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the reserved addresses of DHCP server
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_dhcp_server_reservedaddress"
          params:
            adom: "ansible"
            server: "1" # id
            reserved_address: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address',
        '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'server': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dhcp_server_reservedaddress': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                'description': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'ip': {'type': 'str'},
                'mac': {'type': 'str'},
                'circuit-id': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'circuit-id-type': {'v_range': [['6.2.0', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'remote-id': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'remote-id-type': {'v_range': [['6.2.0', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'type': {'v_range': [['6.2.0', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_server_reservedaddress'),
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
