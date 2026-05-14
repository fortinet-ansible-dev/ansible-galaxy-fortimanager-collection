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
module: fmgr_firewall_internetserviceextension
short_description: Configure Internet Services Extension.
version_added: "2.10.0"
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
    firewall_internetserviceextension:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            disable_entry:
                aliases: ['disable-entry']
                type: list
                elements: dict
                description: Disable entry.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices: ['ipv4', 'ipv6']
                    id:
                        type: int
                        description: Disable entry ID.
                    ip_range:
                        aliases: ['ip-range']
                        type: list
                        elements: dict
                        description: Ip range.
                        suboptions:
                            end_ip:
                                aliases: ['end-ip']
                                type: str
                                description: End IPv4 address.
                            id:
                                type: int
                                description: Disable entry range ID.
                            start_ip:
                                aliases: ['start-ip']
                                type: str
                                description: Start IPv4 address.
                    ip6_range:
                        aliases: ['ip6-range']
                        type: list
                        elements: dict
                        description: Ip6 range.
                        suboptions:
                            end_ip6:
                                aliases: ['end-ip6']
                                type: str
                                description: End IPv6 address.
                            id:
                                type: int
                                description: Disable entry range ID.
                            start_ip6:
                                aliases: ['start-ip6']
                                type: str
                                description: Start IPv6 address.
                    port_range:
                        aliases: ['port-range']
                        type: list
                        elements: dict
                        description: Port range.
                        suboptions:
                            end_port:
                                aliases: ['end-port']
                                type: int
                                description: Ending TCP/UDP/SCTP destination port
                            id:
                                type: int
                                description: Custom entry port range ID.
                            start_port:
                                aliases: ['start-port']
                                type: int
                                description: Starting TCP/UDP/SCTP destination port
                    protocol:
                        type: int
                        description: Integer value for the protocol type as defined by IANA
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices: ['ipv4', 'ipv6']
                    dst:
                        type: list
                        elements: str
                        description: Destination address or address group name.
                    dst6:
                        type: list
                        elements: str
                        description: Destination address6 or address6 group name.
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
            id:
                required: true
                type: list
                elements: str
                description: Internet Service ID in the Internet Service database.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Internet Services Extension.
      fortinet.fortimanager.fmgr_firewall_internetserviceextension:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetserviceextension:
          id: [] # Required variable
          # comment: <string>
          # disable_entry:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     id: <integer>
          #     ip_range:
          #       - end_ip: <string>
          #         id: <integer>
          #         start_ip: <string>
          #     ip6_range:
          #       - end_ip6: <string>
          #         id: <integer>
          #         start_ip6: <string>
          #     port_range:
          #       - end_port: <integer>
          #         id: <integer>
          #         start_port: <integer>
          #     protocol: <integer>
          # entry:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     dst: <list or string>
          #     dst6: <list or string>
          #     id: <integer>
          #     port_range:
          #       - end_port: <integer>
          #         id: <integer>
          #         start_port: <integer>
          #     protocol: <integer>
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service-extension',
        '/pm/config/global/obj/firewall/internet-service-extension'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetserviceextension': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
            'options': {
                'comment': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'disable-entry': {
                    'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ip-range': {
                            'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'start-ip': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'ip6-range': {
                            'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'end-ip6': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'start-ip6': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'port-range': {
                            'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'end-port': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'start-port': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'protocol': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'entry': {
                    'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'dst': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'dst6': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port-range': {
                            'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'end-port': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'start-port': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'protocol': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetserviceextension'),
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
