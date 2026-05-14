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
module: fmgr_fsp_vlan_dynamicmapping_interface_secondaryip
short_description: Second IP address of interface.
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    fsp_vlan_dynamicmapping_interface_secondaryip:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowaccess:
                type: list
                elements: str
                description: Allowaccess.
                choices: ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec',
                          'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm', 'fabric',
                          'speed-test']
            detectprotocol:
                type: list
                elements: str
                description: Detectprotocol.
                choices: ['ping', 'tcp-echo', 'udp-echo']
            detectserver:
                type: str
                description: Detectserver.
            gwdetect:
                type: str
                description: Gwdetect.
                choices: ['disable', 'enable']
            ha_priority:
                aliases: ['ha-priority']
                type: int
                description: Ha priority.
            id:
                type: int
                description: Id.
                required: true
            ip:
                type: str
                description: Ip.
            ping_serv_status:
                aliases: ['ping-serv-status']
                type: int
                description: Ping serv status.
            seq:
                type: int
                description: Seq.
            secip_relay_ip:
                aliases: ['secip-relay-ip']
                type: str
                description: DHCP relay IP address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Second IP address of interface.
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_secondaryip:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vlan: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dynamicmapping_interface_secondaryip:
          id: 0 # Required variable, integer
          # allowaccess: ["https", "ping", "ssh", "snmp", "http", "telnet", "fgfm", "auto-ipsec",
          #               "radius-acct", "probe-response", "capwap", "dnp", "ftm", "fabric",
          #               "speed-test"]
          # detectprotocol: ["ping", "tcp-echo", "udp-echo"]
          # detectserver: <string>
          # gwdetect: <value in [disable, enable]>
          # ha_priority: <integer>
          # ip: <string>
          # ping_serv_status: <integer>
          # seq: <integer>
          # secip_relay_ip: <string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dynamicmapping_interface_secondaryip': {
            'type': 'dict', 'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'allowaccess': {
                    'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']],
                    'type': 'list',
                    'choices': [
                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm',
                        'fabric', 'speed-test'
                    ],
                    'elements': 'str'
                },
                'detectprotocol': {'v_range': [['6.2.3', '7.2.0']], 'type': 'list', 'choices': ['ping', 'tcp-echo', 'udp-echo'], 'elements': 'str'},
                'detectserver': {'v_range': [['6.2.3', '7.2.0']], 'type': 'str'},
                'gwdetect': {'v_range': [['6.2.3', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-priority': {'v_range': [['6.2.3', '7.2.0']], 'type': 'int'},
                'id': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'ping-serv-status': {'v_range': [['6.2.3', '7.2.0']], 'type': 'int'},
                'seq': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'secip-relay-ip': {'v_range': [['7.4.0', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_interface_secondaryip'),
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
