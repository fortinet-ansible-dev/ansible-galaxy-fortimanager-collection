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
module: fmgr_firewall_vip46_dynamicmapping
short_description: Configure IPv4 to IPv6 virtual IPs.
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
    vip46:
        description: The parameter (vip46) in requested url.
        type: str
        required: true
    firewall_vip46_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            arp_reply:
                aliases: ['arp-reply']
                type: str
                description: Arp reply.
                choices: ['disable', 'enable']
            color:
                type: int
                description: Color.
            comment:
                type: str
                description: Comment.
            extip:
                type: str
                description: Extip.
            extport:
                type: str
                description: Extport.
            id:
                type: int
                description: Id.
            ldb_method:
                aliases: ['ldb-method']
                type: str
                description: Ldb method.
                choices: ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt',
                          'first-alive']
            mappedip:
                type: str
                description: Mappedip.
            mappedport:
                type: str
                description: Mappedport.
            monitor:
                type: raw
                description: (list or str) Monitor.
            portforward:
                type: str
                description: Portforward.
                choices: ['disable', 'enable']
            protocol:
                type: str
                description: Protocol.
                choices: ['tcp', 'udp']
            server_type:
                aliases: ['server-type']
                type: str
                description: Server type.
                choices: ['http', 'tcp', 'udp', 'ip']
            src_filter:
                aliases: ['src-filter']
                type: raw
                description: (list) Src filter.
            type:
                type: str
                description: Type.
                choices: ['static-nat', 'server-load-balance']
            uuid:
                type: str
                description: Uuid.
            srcintf_filter:
                aliases: ['srcintf-filter']
                type: raw
                description: (list or str) Interfaces to which the VIP46 applies.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure dynamic mappings of IPv4 to IPv6 virtual IPs
      fortinet.fortimanager.fmgr_firewall_vip46_dynamicmapping:
        bypass_validation: false
        adom: ansible
        vip46: "ansible-test-vip46" # name
        state: present
        firewall_vip46_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          arp_reply: disable
          color: 1
          comment: "ansible-comment"
          id: 1
          ldb_method: static # <value in [static, round-robin, weighted, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of IPv4 to IPv6 virtual IPs
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip46_dynamicmapping"
          params:
            adom: "ansible"
            vip46: "ansible-test-vip46" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping',
        '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip46': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip46_dynamicmapping': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'extip': {'type': 'str'},
                'extport': {'type': 'str'},
                'id': {'type': 'int'},
                'ldb-method': {'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive'], 'type': 'str'},
                'mappedip': {'type': 'str'},
                'mappedport': {'type': 'str'},
                'monitor': {'type': 'raw'},
                'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'choices': ['tcp', 'udp'], 'type': 'str'},
                'server-type': {'choices': ['http', 'tcp', 'udp', 'ip'], 'type': 'str'},
                'src-filter': {'type': 'raw'},
                'type': {'choices': ['static-nat', 'server-load-balance'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'srcintf-filter': {'v_range': [['6.2.7', '6.2.13'], ['6.4.4', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip46_dynamicmapping'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
