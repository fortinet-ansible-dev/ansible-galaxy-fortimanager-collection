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
module: fmgr_log_npuserver_serverinfo
short_description: configure server info.
version_added: "2.2.0"
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
    log_npuserver_serverinfo:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dest_port:
                aliases: ['dest-port']
                type: int
                description: Set the dest port for the log packet
            id:
                type: int
                description: Server id.
                required: true
            ip_family:
                aliases: ['ip-family']
                type: str
                description: Set the version the IP address
                choices: ['v4', 'v6']
            ipv4_server:
                aliases: ['ipv4-server']
                type: str
                description: Set the IPv4 address for the log server
            ipv6_server:
                aliases: ['ipv6-server']
                type: str
                description: Set the IPv6 address for the log server
            source_port:
                aliases: ['source-port']
                type: int
                description: Set the source port for the log packet
            template_tx_timeout:
                aliases: ['template-tx-timeout']
                type: int
                description: Set the template tx timeout
            vdom:
                type: str
                description: Interface connected to the log server is in this virtual domain
            log_transport:
                aliases: ['log-transport']
                type: str
                description: Set transport protocol
                choices: ['udp', 'tcp']
            vdom_:
                type: str
                description: Vdom.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure server info.
      fortinet.fortimanager.fmgr_log_npuserver_serverinfo:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        log_npuserver_serverinfo:
          id: 0 # Required variable, integer
          # dest_port: <integer>
          # ip_family: <value in [v4, v6]>
          # ipv4_server: <string>
          # ipv6_server: <string>
          # source_port: <integer>
          # template_tx_timeout: <integer>
          # vdom: <string>
          # log_transport: <value in [udp, tcp]>
          # vdom_: <string>
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
        '/pm/config/adom/{adom}/obj/log/npu-server/server-info',
        '/pm/config/global/obj/log/npu-server/server-info'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'log_npuserver_serverinfo': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']],
            'options': {
                'dest-port': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'type': 'int'},
                'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'required': True, 'type': 'int'},
                'ip-family': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']],
                    'choices': ['v4', 'v6'],
                    'type': 'str'
                },
                'ipv4-server': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'type': 'str'},
                'ipv6-server': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'type': 'str'},
                'source-port': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'type': 'int'},
                'template-tx-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.4.7'], ['7.6.0', '7.6.4']], 'type': 'int'},
                'vdom': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.0.14'], ['7.2.0', '7.2.10'], ['7.4.0', '7.4.7'], ['7.6.0', '7.6.4']],
                    'type': 'str'
                },
                'log-transport': {'v_range': [['7.4.2', '7.4.7'], ['7.6.0', '7.6.4']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                'vdom_': {'v_range': [['7.2.11', '7.2.12'], ['7.6.4', '7.6.4']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_npuserver_serverinfo'),
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
