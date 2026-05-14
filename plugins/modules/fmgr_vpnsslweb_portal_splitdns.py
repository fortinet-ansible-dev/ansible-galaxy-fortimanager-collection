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
module: fmgr_vpnsslweb_portal_splitdns
short_description: Split DNS for SSL VPN.
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
    portal:
        description: The parameter (portal) in requested url.
        type: str
        required: true
    vpnsslweb_portal_splitdns:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dns_server1:
                aliases: ['dns-server1']
                type: str
                description: DNS server 1.
            dns_server2:
                aliases: ['dns-server2']
                type: str
                description: DNS server 2.
            domains:
                type: str
                description: Split DNS domains used for SSL-VPN clients separated by comma
            id:
                type: int
                description: ID.
                required: true
            ipv6_dns_server1:
                aliases: ['ipv6-dns-server1']
                type: str
                description: IPv6 DNS server 1.
            ipv6_dns_server2:
                aliases: ['ipv6-dns-server2']
                type: str
                description: IPv6 DNS server 2.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Split DNS for SSL VPN.
      fortinet.fortimanager.fmgr_vpnsslweb_portal_splitdns:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        portal: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal_splitdns:
          id: 0 # Required variable, integer
          # dns_server1: <string>
          # dns_server2: <string>
          # domains: <string>
          # ipv6_dns_server1: <string>
          # ipv6_dns_server2: <string>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnsslweb_portal_splitdns': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'dns-server1': {'type': 'str'},
                'dns-server2': {'type': 'str'},
                'domains': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'ipv6-dns-server1': {'type': 'str'},
                'ipv6-dns-server2': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_splitdns'),
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
