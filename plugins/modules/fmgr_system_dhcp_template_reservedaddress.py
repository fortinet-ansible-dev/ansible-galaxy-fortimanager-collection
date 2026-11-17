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
module: fmgr_system_dhcp_template_reservedaddress
short_description: Options for the DHCP server to assign IP settings to specific MAC addresses.
version_added: "2.16.0"
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
  template:
    description: The parameter (template) in requested url.
    type: str
    required: true
  system_dhcp_template_reservedaddress:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Options for the DHCP server to configure the client with the reserved MAC address.
        choices: ['assign', 'block', 'reserved']
      circuit_id:
        aliases: ['circuit-id']
        type: str
        description: Option 82 circuit-ID of the client that will get the reserved IP address.
      circuit_id_type:
        aliases: ['circuit-id-type']
        type: str
        description: DHCP option type.
        choices: ['hex', 'string']
      description:
        type: str
        description: Description.
      id:
        type: int
        description: ID.
        required: true
      ip_index:
        aliases: ['ip-index']
        type: int
        description: Index of IP address to be reserved for the MAC address.
      mac:
        type: str
        description: MAC address of the client that will get the reserved IP address.
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
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Options for the DHCP server to assign IP settings to specific MAC addresses.
      fortinet.fortimanager.fmgr_system_dhcp_template_reservedaddress:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        template: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp_template_reservedaddress:
          id: 0 # Required variable, integer
          # action: <value in [assign, block, reserved]>
          # circuit_id: <string>
          # circuit_id_type: <value in [hex, string]>
          # description: <string>
          # ip_index: <integer>
          # mac: <string>
          # remote_id: <string>
          # remote_id_type: <value in [hex, string]>
          # type: <value in [mac, option82]>
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
        '/pm/config/adom/{adom}/obj/system/dhcp/template/{template}/reserved-address',
        '/pm/config/global/obj/system/dhcp/template/{template}/reserved-address'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'template': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dhcp_template_reservedaddress': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'action': {'v_range': [['8.0.1', '']], 'choices': ['assign', 'block', 'reserved'], 'type': 'str'},
                'circuit-id': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'circuit-id-type': {'v_range': [['8.0.1', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'description': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'id': {'v_range': [['8.0.1', '']], 'required': True, 'type': 'int'},
                'ip-index': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'mac': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'remote-id': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'remote-id-type': {'v_range': [['8.0.1', '']], 'choices': ['hex', 'string'], 'type': 'str'},
                'type': {'v_range': [['8.0.1', '']], 'choices': ['mac', 'option82'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp_template_reservedaddress'),
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
