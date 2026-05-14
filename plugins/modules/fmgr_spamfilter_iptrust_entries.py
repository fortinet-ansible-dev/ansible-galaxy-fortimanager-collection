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
module: fmgr_spamfilter_iptrust_entries
short_description: Spam filter trusted IP addresses.
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
    iptrust:
        description: The parameter (iptrust) in requested url.
        type: str
        required: true
    spamfilter_iptrust_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_type:
                aliases: ['addr-type']
                type: str
                description: Type of address.
                choices: ['ipv4', 'ipv6']
            id:
                type: int
                description: Trusted IP entry ID.
                required: true
            ip4_subnet:
                aliases: ['ip4-subnet']
                type: str
                description: IPv4 network address or network address/subnet mask bits.
            ip6_subnet:
                aliases: ['ip6-subnet']
                type: str
                description: IPv6 network address/subnet mask bits.
            status:
                type: str
                description: Enable/disable status.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Spam filter trusted IP addresses.
      fortinet.fortimanager.fmgr_spamfilter_iptrust_entries:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        iptrust: <your own value>
        state: present # <value in [present, absent]>
        spamfilter_iptrust_entries:
          id: 0 # Required variable, integer
          # addr_type: <value in [ipv4, ipv6]>
          # ip4_subnet: <string>
          # ip6_subnet: <string>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries',
        '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'iptrust': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'spamfilter_iptrust_entries': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
            'options': {
                'addr-type': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'id': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'required': True, 'type': 'int'},
                'ip4-subnet': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'ip6-subnet': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                'status': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'spamfilter_iptrust_entries'),
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
