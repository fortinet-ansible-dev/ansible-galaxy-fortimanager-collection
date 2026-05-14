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
module: fmgr_webproxy_forwardserver
short_description: Configure forward-server addresses.
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
    webproxy_forwardserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_type:
                aliases: ['addr-type']
                type: str
                description: Address type of the forwarding proxy server
                choices: ['fqdn', 'ip', 'ipv6']
            comment:
                type: str
                description: Comment.
            fqdn:
                type: str
                description: Forward server Fully Qualified Domain Name
            healthcheck:
                type: str
                description: Enable/disable forward server health checking.
                choices: ['disable', 'enable']
            ip:
                type: str
                description: Forward proxy server IP address.
            monitor:
                type: str
                description: URL for forward server health check monitoring
            name:
                type: str
                description: Server name.
                required: true
            port:
                type: int
                description: Port number that the forwarding server expects to receive HTTP sessions on
            server_down_option:
                aliases: ['server-down-option']
                type: str
                description: Action to take when the forward server is found to be down
                choices: ['block', 'pass']
            password:
                type: raw
                description: (list) HTTP authentication password.
            username:
                type: str
                description: HTTP authentication user name.
            ipv6:
                type: str
                description: Forward proxy server IPv6 address.
            masquerade:
                type: str
                description: Enable/disable use of the of the IP address of the outgoing interface as the client IP address
                choices: ['disable', 'enable']
            interface:
                type: raw
                description: (list) Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            ippool:
                type: raw
                description: (list) Ippool.
            protocol:
                type: list
                elements: str
                description: Protocol.
                choices: ['http', 'ftp', 'socks']
            authentication:
                type: str
                description: Authentication type.
                choices: ['disabled', 'immediately', 'upon-challenge']
            user:
                type: str
                description: User name of basic proxy authentication.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure forward-server addresses.
      fortinet.fortimanager.fmgr_webproxy_forwardserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        webproxy_forwardserver:
          name: "your value" # Required variable, string
          # addr_type: <value in [fqdn, ip, ipv6]>
          # comment: <string>
          # fqdn: <string>
          # healthcheck: <value in [disable, enable]>
          # ip: <string>
          # monitor: <string>
          # port: <integer>
          # server_down_option: <value in [block, pass]>
          # password: <list or string>
          # username: <string>
          # ipv6: <string>
          # masquerade: <value in [disable, enable]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # vrf_select: <integer>
          # ippool: <list or string>
          # protocol: ["http", "ftp", "socks"]
          # authentication: <value in [disabled, immediately, upon-challenge]>
          # user: <string>
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
        '/pm/config/adom/{adom}/obj/web-proxy/forward-server',
        '/pm/config/global/obj/web-proxy/forward-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webproxy_forwardserver': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'addr-type': {'choices': ['fqdn', 'ip', 'ipv6'], 'type': 'str'},
                'comment': {'type': 'str'},
                'fqdn': {'type': 'str'},
                'healthcheck': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'type': 'str'},
                'monitor': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'port': {'type': 'int'},
                'server-down-option': {'choices': ['block', 'pass'], 'type': 'str'},
                'password': {'v_range': [['6.4.0', '']], 'no_log': True, 'type': 'raw'},
                'username': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'ipv6': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'masquerade': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'interface-select-method': {'v_range': [['7.6.2', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'ippool': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'raw'},
                'protocol': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'choices': ['http', 'ftp', 'socks'], 'elements': 'str'},
                'authentication': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disabled', 'immediately', 'upon-challenge'], 'type': 'str'},
                'user': {'v_range': [['7.4.8', '7.4.10']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_forwardserver'),
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
