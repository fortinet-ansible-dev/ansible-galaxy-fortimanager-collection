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
module: fmgr_wagprofile
short_description: Configure wireless access gateway
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
    wagprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            dhcp_ip_addr:
                aliases: ['dhcp-ip-addr']
                type: str
                description: IP address of the monitoring DHCP request packet sent through the tunnel.
            name:
                type: str
                description: Tunnel profile name.
                required: true
            ping_interval:
                aliases: ['ping-interval']
                type: int
                description: Interval between two tunnel monitoring echo packets
            ping_number:
                aliases: ['ping-number']
                type: int
                description: Number of the tunnel monitoring echo packets
            return_packet_timeout:
                aliases: ['return-packet-timeout']
                type: int
                description: Window of time for the return packets from the tunnels remote end
            tunnel_type:
                aliases: ['tunnel-type']
                type: str
                description: Tunnel type.
                choices: ['gre', 'l2tpv3']
            wag_ip:
                aliases: ['wag-ip']
                type: str
                description: IP Address of the wireless access gateway.
            wag_port:
                aliases: ['wag-port']
                type: int
                description: UDP port of the wireless access gateway.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure wireless access gateway
      fortinet.fortimanager.fmgr_wagprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        wagprofile:
          name: "your value" # Required variable, string
          # comment: <string>
          # dhcp_ip_addr: <string>
          # ping_interval: <integer>
          # ping_number: <integer>
          # return_packet_timeout: <integer>
          # tunnel_type: <value in [gre, l2tpv3]>
          # wag_ip: <string>
          # wag_port: <integer>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile',
        '/pm/config/global/obj/wireless-controller/wag-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wagprofile': {
            'type': 'dict', 'v_range': [['6.2.3', '']],
            'options': {
                'comment': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'dhcp-ip-addr': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'name': {'v_range': [['6.2.3', '']], 'required': True, 'type': 'str'},
                'ping-interval': {'v_range': [['6.2.3', '']], 'type': 'int'},
                'ping-number': {'v_range': [['6.2.3', '']], 'type': 'int'},
                'return-packet-timeout': {'v_range': [['6.2.3', '']], 'type': 'int'},
                'tunnel-type': {'v_range': [['6.2.3', '']], 'choices': ['gre', 'l2tpv3'], 'type': 'str'},
                'wag-ip': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'wag-port': {'v_range': [['6.2.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wagprofile'),
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
