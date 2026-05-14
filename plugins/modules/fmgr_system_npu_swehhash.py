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
module: fmgr_system_npu_swehhash
short_description: Configure switch enhanced hashing.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_npu_swehhash:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            computation:
                type: str
                description: Set hashing computation.
                choices: ['xor16', 'xor8', 'xor4', 'crc16']
            destination_ip_lower_16:
                aliases: ['destination-ip-lower-16']
                type: str
                description: Include/exclude destination IP address lower 16 bits.
                choices: ['include', 'exclude']
            destination_ip_upper_16:
                aliases: ['destination-ip-upper-16']
                type: str
                description: Include/exclude destination IP address upper 16 bits.
                choices: ['include', 'exclude']
            destination_port:
                aliases: ['destination-port']
                type: str
                description: Include/exclude destination port if TCP/UDP.
                choices: ['include', 'exclude']
            ip_protocol:
                aliases: ['ip-protocol']
                type: str
                description: Include/exclude IP protocol.
                choices: ['include', 'exclude']
            netmask_length:
                aliases: ['netmask-length']
                type: int
                description: Network mask length.
            source_ip_lower_16:
                aliases: ['source-ip-lower-16']
                type: str
                description: Include/exclude source IP address lower 16 bits.
                choices: ['include', 'exclude']
            source_ip_upper_16:
                aliases: ['source-ip-upper-16']
                type: str
                description: Include/exclude source IP address upper 16 bits.
                choices: ['include', 'exclude']
            source_port:
                aliases: ['source-port']
                type: str
                description: Include/exclude source port if TCP/UDP.
                choices: ['include', 'exclude']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure switch enhanced hashing.
      fortinet.fortimanager.fmgr_system_npu_swehhash:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        system_npu_swehhash:
          # computation: <value in [xor16, xor8, xor4, ...]>
          # destination_ip_lower_16: <value in [include, exclude]>
          # destination_ip_upper_16: <value in [include, exclude]>
          # destination_port: <value in [include, exclude]>
          # ip_protocol: <value in [include, exclude]>
          # netmask_length: <integer>
          # source_ip_lower_16: <value in [include, exclude]>
          # source_ip_upper_16: <value in [include, exclude]>
          # source_port: <value in [include, exclude]>
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
        '/pm/config/adom/{adom}/obj/system/npu/sw-eh-hash',
        '/pm/config/global/obj/system/npu/sw-eh-hash'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_swehhash': {
            'type': 'dict', 'v_range': [['7.0.1', '']],
            'options': {
                'computation': {'v_range': [['7.0.1', '']], 'choices': ['xor16', 'xor8', 'xor4', 'crc16'], 'type': 'str'},
                'destination-ip-lower-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'destination-ip-upper-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'destination-port': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'ip-protocol': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'netmask-length': {'v_range': [['7.0.1', '']], 'type': 'int'},
                'source-ip-lower-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'source-ip-upper-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'source-port': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_swehhash'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
