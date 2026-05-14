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
module: fmgr_hotspot20_h2qpconncapability
short_description: Configure connection capability.
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
    hotspot20_h2qpconncapability:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            esp_port:
                aliases: ['esp-port']
                type: str
                description: Set ESP port service
                choices: ['closed', 'open', 'unknown']
            ftp_port:
                aliases: ['ftp-port']
                type: str
                description: Set FTP port service status.
                choices: ['closed', 'open', 'unknown']
            http_port:
                aliases: ['http-port']
                type: str
                description: Set HTTP port service status.
                choices: ['closed', 'open', 'unknown']
            icmp_port:
                aliases: ['icmp-port']
                type: str
                description: Set ICMP port service status.
                choices: ['closed', 'open', 'unknown']
            ikev2_port:
                aliases: ['ikev2-port']
                type: str
                description: Set IKEv2 port service for IPsec VPN status.
                choices: ['closed', 'open', 'unknown']
            ikev2_xx_port:
                aliases: ['ikev2-xx-port']
                type: str
                description: Set UDP port 4500
                choices: ['closed', 'open', 'unknown']
            name:
                type: str
                description: Connection capability name.
                required: true
            pptp_vpn_port:
                aliases: ['pptp-vpn-port']
                type: str
                description: Set Point to Point Tunneling Protocol
                choices: ['closed', 'open', 'unknown']
            ssh_port:
                aliases: ['ssh-port']
                type: str
                description: Set SSH port service status.
                choices: ['closed', 'open', 'unknown']
            tls_port:
                aliases: ['tls-port']
                type: str
                description: Set TLS VPN
                choices: ['closed', 'open', 'unknown']
            voip_tcp_port:
                aliases: ['voip-tcp-port']
                type: str
                description: Set VoIP TCP port service status.
                choices: ['closed', 'open', 'unknown']
            voip_udp_port:
                aliases: ['voip-udp-port']
                type: str
                description: Set VoIP UDP port service status.
                choices: ['closed', 'open', 'unknown']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure connection capability.
      fortinet.fortimanager.fmgr_hotspot20_h2qpconncapability:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_h2qpconncapability:
          name: "your value" # Required variable, string
          # esp_port: <value in [closed, open, unknown]>
          # ftp_port: <value in [closed, open, unknown]>
          # http_port: <value in [closed, open, unknown]>
          # icmp_port: <value in [closed, open, unknown]>
          # ikev2_port: <value in [closed, open, unknown]>
          # ikev2_xx_port: <value in [closed, open, unknown]>
          # pptp_vpn_port: <value in [closed, open, unknown]>
          # ssh_port: <value in [closed, open, unknown]>
          # tls_port: <value in [closed, open, unknown]>
          # voip_tcp_port: <value in [closed, open, unknown]>
          # voip_udp_port: <value in [closed, open, unknown]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_h2qpconncapability': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'esp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ftp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'http-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'icmp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ikev2-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ikev2-xx-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'pptp-vpn-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ssh-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'tls-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'voip-tcp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'voip-udp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_h2qpconncapability'),
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
