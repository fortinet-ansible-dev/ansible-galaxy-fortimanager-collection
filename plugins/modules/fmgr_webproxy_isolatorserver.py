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
module: fmgr_webproxy_isolatorserver
short_description: Configure forward-server addresses.
version_added: "2.14.0"
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
    webproxy_isolatorserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_type:
                aliases: ['addr-type']
                type: str
                description: Address type of the forwarding proxy server
                choices: ['fqdn', 'ipv6', 'ip']
            comment:
                type: str
                description: Comment.
            fqdn:
                type: str
                description: Forward server Fully Qualified Domain Name
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            ip:
                type: str
                description: Forward proxy server IP address.
            ipv6:
                type: str
                description: Forward proxy server IPv6 address.
            name:
                type: str
                description: Server name.
                required: true
            port:
                type: int
                description: Port number that the forwarding server expects to receive HTTP sessions on
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            masquerade:
                type: str
                description: Enable/disable use of the of the IP address of the outgoing interface as the client IP address
                choices: ['disable', 'enable']
            ippool:
                type: list
                elements: str
                description: Ippool.
            protocol:
                type: list
                elements: str
                description: Protocol.
                choices: ['http', 'ftp', 'socks']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure forward-server addresses.
      fortinet.fortimanager.fmgr_webproxy_isolatorserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        webproxy_isolatorserver:
          name: "your value" # Required variable, string
          # addr_type: <value in [fqdn, ipv6, ip]>
          # comment: <string>
          # fqdn: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ip: <string>
          # ipv6: <string>
          # port: <integer>
          # vrf_select: <integer>
          # masquerade: <value in [disable, enable]>
          # ippool: <list or string>
          # protocol: ["http", "ftp", "socks"]
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
        '/pm/config/adom/{adom}/obj/web-proxy/isolator-server',
        '/pm/config/global/obj/web-proxy/isolator-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webproxy_isolatorserver': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']],
            'options': {
                'addr-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'choices': ['fqdn', 'ipv6', 'ip'], 'type': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'fqdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.6.2', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'ipv6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']], 'type': 'int'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'masquerade': {'v_range': [['7.4.8', '7.4.10'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ippool': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'choices': ['http', 'ftp', 'socks'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_isolatorserver'),
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
