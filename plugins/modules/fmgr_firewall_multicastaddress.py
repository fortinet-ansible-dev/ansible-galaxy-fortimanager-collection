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
module: fmgr_firewall_multicastaddress
short_description: Configure multicast addresses.
version_added: "1.0.0"
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
    firewall_multicastaddress:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            associated_interface:
                aliases: ['associated-interface']
                type: str
                description: Interface associated with the address object.
            color:
                type: int
                description: Integer value to determine the color of the icon in the GUI
            comment:
                type: str
                description: Comment.
            end_ip:
                aliases: ['end-ip']
                type: str
                description: Final IPv4 address
            name:
                type: str
                description: Multicast address name.
                required: true
            start_ip:
                aliases: ['start-ip']
                type: str
                description: First IPv4 address
            subnet:
                type: str
                description: Broadcast address and subnet.
            tagging:
                type: list
                elements: dict
                description: Tagging.
                suboptions:
                    category:
                        type: str
                        description: Tag category.
                    name:
                        type: str
                        description: Tagging entry name.
                    tags:
                        type: raw
                        description: (list) Tags.
            type:
                type: str
                description: Type of address object
                choices: ['multicastrange', 'broadcastmask']
            visibility:
                type: str
                description: Enable/disable visibility of the multicast address on the GUI.
                choices: ['disable', 'enable']
            tags:
                type: str
                description: Names of object-tags
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
    - name: Configure multicast addresses.
      fortinet.fortimanager.fmgr_firewall_multicastaddress:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_multicastaddress:
          color: 0
          comment: "ansible-comment"
          name: "ansible-test"
          subnet: "222.222.221.0/24"
          type: broadcastmask # <value in [multicastrange, broadcastmask]>
          visibility: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 multicast addresses
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_multicastaddress"
          params:
            adom: "ansible"
            multicast_address: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/multicast-address',
        '/pm/config/global/obj/firewall/multicast-address'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_multicastaddress': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'associated-interface': {'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'end-ip': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'start-ip': {'type': 'str'},
                'subnet': {'type': 'str'},
                'tagging': {
                    'type': 'list',
                    'options': {'category': {'type': 'str'}, 'name': {'type': 'str'}, 'tags': {'type': 'raw'}},
                    'elements': 'dict'
                },
                'type': {'choices': ['multicastrange', 'broadcastmask'], 'type': 'str'},
                'visibility': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.2.0', '6.4.15']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_multicastaddress'),
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
