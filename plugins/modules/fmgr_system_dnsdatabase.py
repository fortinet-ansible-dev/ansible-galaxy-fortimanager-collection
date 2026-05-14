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
module: fmgr_system_dnsdatabase
short_description: Configure DNS databases.
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
    system_dnsdatabase:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allow_transfer:
                aliases: ['allow-transfer']
                type: list
                elements: str
                description: DNS zone transfer IP address list.
            authoritative:
                type: str
                description: Enable/disable authoritative zone.
                choices: ['disable', 'enable']
            contact:
                type: str
                description: Email address of the administrator for this zone.
            dns_entry:
                aliases: ['dns-entry']
                type: list
                elements: dict
                description: Dns entry.
                suboptions:
                    canonical_name:
                        aliases: ['canonical-name']
                        type: str
                        description: Canonical name of the host.
                    hostname:
                        type: str
                        description: Name of the host.
                    id:
                        type: int
                        description: DNS entry ID.
                    ip:
                        type: str
                        description: IPv4 address of the host.
                    ipv6:
                        type: str
                        description: IPv6 address of the host.
                    preference:
                        type: int
                        description: DNS entry preference
                    status:
                        type: str
                        description: Enable/disable resource record status.
                        choices: ['disable', 'enable']
                    ttl:
                        type: int
                        description: Time-to-live for this entry
                    type:
                        type: str
                        description: Resource record type.
                        choices: ['NS', 'MX', 'CNAME', 'A', 'AAAA', 'PTR', 'PTR_V6']
            domain:
                type: str
                description: Domain name.
            forwarder:
                type: list
                elements: str
                description: DNS zone forwarder IP address list.
            forwarder6:
                type: str
                description: Forwarder IPv6 address.
            ip_primary:
                aliases: ['ip-primary']
                type: str
                description: IP address of primary DNS server.
            name:
                type: str
                description: Zone name.
                required: true
            primary_name:
                aliases: ['primary-name']
                type: str
                description: Domain name of the default DNS server for this zone.
            rr_max:
                aliases: ['rr-max']
                type: int
                description: Maximum number of resource records
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP for forwarding to DNS server.
            source_ip6:
                aliases: ['source-ip6']
                type: str
                description: IPv6 source IP address for forwarding to DNS server.
            status:
                type: str
                description: Enable/disable this DNS zone.
                choices: ['disable', 'enable']
            ttl:
                type: int
                description: Default time-to-live value for the entries of this DNS zone
            type:
                type: str
                description: Zone type
                choices: ['primary', 'secondary', 'master', 'slave']
            view:
                type: str
                description: Zone view
                choices: ['shadow', 'public', 'shadow-ztna', 'proxy']
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            source_ip_interface:
                aliases: ['source-ip-interface']
                type: list
                elements: str
                description: IP address of the specified interface as the source IP address.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            ip_master:
                aliases: ['ip-master']
                type: str
                description: IP address of master DNS server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure DNS databases.
      fortinet.fortimanager.fmgr_system_dnsdatabase:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_dnsdatabase:
          name: "your value" # Required variable, string
          # allow_transfer: <list or string>
          # authoritative: <value in [disable, enable]>
          # contact: <string>
          # dns_entry:
          #   - canonical_name: <string>
          #     hostname: <string>
          #     id: <integer>
          #     ip: <string>
          #     ipv6: <string>
          #     preference: <integer>
          #     status: <value in [disable, enable]>
          #     ttl: <integer>
          #     type: <value in [NS, MX, CNAME, ...]>
          # domain: <string>
          # forwarder: <list or string>
          # forwarder6: <string>
          # ip_primary: <string>
          # primary_name: <string>
          # rr_max: <integer>
          # source_ip: <string>
          # source_ip6: <string>
          # status: <value in [disable, enable]>
          # ttl: <integer>
          # type: <value in [primary, secondary, master, ...]>
          # view: <value in [shadow, public, shadow-ztna, ...]>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # interface: <list or string>
          # source_ip_interface: <list or string>
          # vrf_select: <integer>
          # ip_master: <string>
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
        '/pm/config/adom/{adom}/obj/system/dns-database',
        '/pm/config/global/obj/system/dns-database'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_dnsdatabase': {
            'type': 'dict', 'v_range': [['7.6.4', '7.6.4']],
            'options': {
                'allow-transfer': {'v_range': [['7.6.4', '7.6.4']], 'type': 'list', 'elements': 'str'},
                'authoritative': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'contact': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'dns-entry': {
                    'v_range': [['7.6.4', '7.6.4']],
                    'type': 'list',
                    'options': {
                        'canonical-name': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                        'hostname': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                        'id': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                        'ip': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                        'ipv6': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                        'preference': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                        'status': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ttl': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                        'type': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['NS', 'MX', 'CNAME', 'A', 'AAAA', 'PTR', 'PTR_V6'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'domain': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'forwarder': {'v_range': [['7.6.4', '7.6.4']], 'type': 'list', 'elements': 'str'},
                'forwarder6': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'ip-primary': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '7.6.4']], 'required': True, 'type': 'str'},
                'primary-name': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'rr-max': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                'source-ip': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'},
                'status': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ttl': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                'type': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['primary', 'secondary', 'master', 'slave'], 'type': 'str'},
                'view': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['shadow', 'public', 'shadow-ztna', 'proxy'], 'type': 'str'},
                'interface-select-method': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'interface': {'v_range': [['7.6.4', '7.6.4']], 'type': 'list', 'elements': 'str'},
                'source-ip-interface': {'v_range': [['7.6.4', '7.6.4']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '7.6.4']], 'type': 'int'},
                'ip-master': {'v_range': [['7.6.4', '7.6.4']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dnsdatabase'),
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
