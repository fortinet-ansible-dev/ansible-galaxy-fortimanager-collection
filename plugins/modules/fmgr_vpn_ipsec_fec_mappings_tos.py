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
module: fmgr_vpn_ipsec_fec_mappings_tos
short_description: FEC redundancy mapping table for specific type of service
version_added: "2.15.0"
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
  fec:
    description: The parameter (fec) in requested url.
    type: str
    required: true
  mappings:
    description: The parameter (mappings) in requested url.
    type: str
    required: true
  vpn_ipsec_fec_mappings_tos:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      base:
        type: int
        description: Number of base FEC packets
      redundant:
        type: int
        description: Number of redundant FEC packets
      seqno:
        type: int
        description: Sequence number
      tos:
        type: str
        description: Type of service bit pattern.
      tos_mask:
        aliases: ['tos-mask']
        type: str
        description: Type of service evaluated bits.
'''

EXAMPLES = '''
- name: Test IPsec FEC type-of-service mappings
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent IPsec FEC profile
      fortinet.fortimanager.fmgr_vpn_ipsec_fec:
        enable_log: true
        adom: root
        state: present
        vpn_ipsec_fec:
          name: test_fec

    - name: Create the parent IPsec FEC mapping
      fortinet.fortimanager.fmgr_vpn_ipsec_fec_mappings:
        enable_log: true
        adom: root
        fec: test_fec
        state: present
        vpn_ipsec_fec_mappings:
          base: 10
          redundant: 2
          seqno: 1

    - name: Configure an IPsec FEC type-of-service mapping
      fortinet.fortimanager.fmgr_vpn_ipsec_fec_mappings_tos:
        enable_log: true
        adom: root
        fec: test_fec
        mappings: "1"
        state: present
        vpn_ipsec_fec_mappings_tos:
          base: 10
          redundant: 2
          seqno: 1
          tos: "0x00"
          tos_mask: "0xff"
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
        '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}/tos',
        '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}/tos'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'fec': {'required': True, 'type': 'str'},
        'mappings': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpn_ipsec_fec_mappings_tos': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'base': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'redundant': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'seqno': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'tos': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'tos-mask': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_fec_mappings_tos'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
