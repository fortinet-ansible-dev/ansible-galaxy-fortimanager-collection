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
module: fmgr_system_sniffer
short_description: Interface sniffer.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_sniffer:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            host:
                type: str
                description: Hosts to filter for in sniffer traffic
            id:
                type: int
                description: Sniffer ID.
                required: true
            interface:
                type: str
                description: Interface.
            ipv6:
                type: str
                description:
                    - Enable/disable sniffing IPv6 packets.
                    - disable - Disable sniffer for IPv6 packets.
                    - enable - Enable sniffer for IPv6 packets.
                choices: ['disable', 'enable']
            max_packet_count:
                aliases: ['max-packet-count']
                type: int
                description: Maximum packet count
            non_ip:
                aliases: ['non-ip']
                type: str
                description:
                    - Enable/disable sniffing non-IP packets.
                    - disable - Disable sniffer for non-IP packets.
                    - enable - Enable sniffer for non-IP packets.
                choices: ['disable', 'enable']
            port:
                type: str
                description: Ports to sniff
            protocol:
                type: str
                description: Integer value for the protocol type as defined by IANA
            vlan:
                type: str
                description: List of VLANs to sniff.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Interface sniffer.
      fortinet.fortimanager.fmgr_system_sniffer:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_sniffer:
          id: 0 # Required variable, integer
          # host: <string>
          # interface: <string>
          # ipv6: <value in [disable, enable]>
          # max_packet_count: <integer>
          # non_ip: <value in [disable, enable]>
          # port: <string>
          # protocol: <string>
          # vlan: <string>
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
        '/cli/global/system/sniffer'
    ]
    module_arg_spec = {
        'system_sniffer': {
            'type': 'dict', 'v_range': [['6.2.2', '']],
            'options': {
                'host': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'id': {'v_range': [['6.2.2', '']], 'required': True, 'type': 'int'},
                'interface': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'ipv6': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-packet-count': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'non-ip': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'protocol': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'vlan': {'v_range': [['6.2.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sniffer'),
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
