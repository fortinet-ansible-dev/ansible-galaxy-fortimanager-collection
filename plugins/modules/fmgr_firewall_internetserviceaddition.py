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
module: fmgr_firewall_internetserviceaddition
short_description: Configure Internet Services Addition.
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
    firewall_internetserviceaddition:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    id:
                        type: int
                        description: Entry ID
                    port_range:
                        aliases: ['port-range']
                        type: list
                        elements: dict
                        description: Port range.
                        suboptions:
                            end_port:
                                aliases: ['end-port']
                                type: int
                                description: Integer value for ending TCP/UDP/SCTP destination port in range
                            id:
                                type: int
                                description: Custom entry port range ID.
                            start_port:
                                aliases: ['start-port']
                                type: int
                                description: Integer value for starting TCP/UDP/SCTP destination port in range
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices: ['ipv4', 'ipv6']
            id:
                type: str
                description: Internet Service ID in the Internet Service database.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Internet Services Addition.
      fortinet.fortimanager.fmgr_firewall_internetserviceaddition:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetserviceaddition:
          id: "your value" # Required variable, string
          # comment: <string>
          # entry:
          #   - id: <integer>
          #     port_range:
          #       - end_port: <integer>
          #         id: <integer>
          #         start_port: <integer>
          #     protocol: <integer>
          #     addr_mode: <value in [ipv4, ipv6]>
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service-addition',
        '/pm/config/global/obj/firewall/internet-service-addition'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetserviceaddition': {
            'type': 'dict', 'v_range': [['6.2.2', '']],
            'options': {
                'comment': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'entry': {
                    'v_range': [['6.2.2', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'port-range': {
                            'v_range': [['6.2.2', '']],
                            'type': 'list',
                            'options': {
                                'end-port': {'v_range': [['6.2.2', '']], 'type': 'int'},
                                'id': {'v_range': [['6.2.2', '']], 'type': 'int'},
                                'start-port': {'v_range': [['6.2.2', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'protocol': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'addr-mode': {'v_range': [['7.2.1', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['6.2.2', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetserviceaddition'),
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
