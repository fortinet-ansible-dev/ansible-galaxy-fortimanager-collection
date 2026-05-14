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
module: fmgr_icap_server
short_description: Configure ICAP servers.
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
    icap_server:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ip_address:
                aliases: ['ip-address']
                type: str
                description: IPv4 address of the ICAP server.
            ip_version:
                aliases: ['ip-version']
                type: str
                description: IP version.
                choices: ['4', '6']
            ip6_address:
                aliases: ['ip6-address']
                type: str
                description: IPv6 address of the ICAP server.
            max_connections:
                aliases: ['max-connections']
                type: int
                description: Maximum number of concurrent connections to ICAP server.
            name:
                type: str
                description: Server name.
                required: true
            port:
                type: int
                description: ICAP server port.
            secure:
                type: str
                description: Enable/disable secure connection to ICAP server.
                choices: ['disable', 'enable']
            ssl_cert:
                aliases: ['ssl-cert']
                type: str
                description: CA certificate name.
            addr_type:
                aliases: ['addr-type']
                type: str
                description: Address type of the remote ICAP server
                choices: ['fqdn', 'ip4', 'ip6']
            fqdn:
                type: str
                description: ICAP remote server Fully Qualified Domain Name
            healthcheck:
                type: str
                description: Enable/disable ICAP remote server health checking.
                choices: ['disable', 'enable']
            healthcheck_service:
                aliases: ['healthcheck-service']
                type: str
                description: ICAP Service name to use for health checks.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure ICAP servers.
      fortinet.fortimanager.fmgr_icap_server:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        icap_server:
          name: "your value" # Required variable, string
          # ip_address: <string>
          # ip_version: <value in [4, 6]>
          # ip6_address: <string>
          # max_connections: <integer>
          # port: <integer>
          # secure: <value in [disable, enable]>
          # ssl_cert: <string>
          # addr_type: <value in [fqdn, ip4, ip6]>
          # fqdn: <string>
          # healthcheck: <value in [disable, enable]>
          # healthcheck_service: <string>
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
        '/pm/config/adom/{adom}/obj/icap/server',
        '/pm/config/global/obj/icap/server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'icap_server': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'ip-address': {'type': 'str'},
                'ip-version': {'choices': ['4', '6'], 'type': 'str'},
                'ip6-address': {'type': 'str'},
                'max-connections': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'port': {'type': 'int'},
                'secure': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-cert': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'addr-type': {'v_range': [['7.2.0', '']], 'choices': ['fqdn', 'ip4', 'ip6'], 'type': 'str'},
                'fqdn': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'healthcheck': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'healthcheck-service': {'v_range': [['7.2.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_server'),
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
