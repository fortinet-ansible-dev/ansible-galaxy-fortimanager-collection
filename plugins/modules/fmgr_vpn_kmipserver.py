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
module: fmgr_vpn_kmipserver
short_description: KMIP server entry configuration.
version_added: "2.12.0"
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
    vpn_kmipserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            name:
                type: str
                description: KMIP server entry name.
                required: true
            password:
                type: list
                elements: str
                description: Password to use for connectivity to the KMIP server.
            server_identity_check:
                aliases: ['server-identity-check']
                type: str
                description: Enable/disable KMIP server identity check
                choices: ['disable', 'enable']
            server_list:
                aliases: ['server-list']
                type: list
                elements: dict
                description: Server list.
                suboptions:
                    cert:
                        type: list
                        elements: str
                        description: Client certificate to use for connectivity to the KMIP server.
                    id:
                        type: int
                        description: ID
                    port:
                        type: int
                        description: KMIP server port.
                    server:
                        type: str
                        description: KMIP server FQDN or IP address.
                    status:
                        type: str
                        description: Enable/disable KMIP server.
                        choices: ['disable', 'enable']
            source_ip:
                aliases: ['source-ip']
                type: str
                description: FortiGate IP address to be used for communication with the KMIP server.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices: ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3']
            username:
                type: str
                description: User name to use for connectivity to the KMIP server.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: KMIP server entry configuration.
      fortinet.fortimanager.fmgr_vpn_kmipserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpn_kmipserver:
          name: "your value" # Required variable, string
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # password: <list or string>
          # server_identity_check: <value in [disable, enable]>
          # server_list:
          #   - cert: <list or string>
          #     id: <integer>
          #     port: <integer>
          #     server: <string>
          #     status: <value in [disable, enable]>
          # source_ip: <string>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # username: <string>
          # vrf_select: <integer>
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
        '/pm/config/adom/{adom}/obj/vpn/kmip-server',
        '/pm/config/global/obj/vpn/kmip-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpn_kmipserver': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'server-identity-check': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-list': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'cert': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'port': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'server': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'source-ip': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.6.4', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'username': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_kmipserver'),
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
