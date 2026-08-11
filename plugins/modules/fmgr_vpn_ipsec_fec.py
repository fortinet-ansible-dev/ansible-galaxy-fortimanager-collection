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
module: fmgr_vpn_ipsec_fec
short_description: Configure Forward Error Correction
version_added: "2.1.0"
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
  vpn_ipsec_fec:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      mappings:
        type: list
        elements: dict
        description: Mappings.
        suboptions:
          bandwidth_bi_threshold:
            aliases: ['bandwidth-bi-threshold']
            type: int
            description: Apply FEC parameters when available bi-bandwidth is >= threshold
          bandwidth_down_threshold:
            aliases: ['bandwidth-down-threshold']
            type: int
            description: Apply FEC parameters when available down bandwidth is >= threshold
          bandwidth_up_threshold:
            aliases: ['bandwidth-up-threshold']
            type: int
            description: Apply FEC parameters when available up bandwidth is >= threshold
          base:
            type: int
            description: Number of base FEC packets
          latency_threshold:
            aliases: ['latency-threshold']
            type: int
            description: Apply FEC parameters when latency is
          packet_loss_threshold:
            aliases: ['packet-loss-threshold']
            type: int
            description: Apply FEC parameters when packet loss is >= threshold
          redundant:
            type: int
            description: Number of redundant FEC packets
          seqno:
            type: int
            description: Sequence number
          bandwidth_bi_threshold_negate:
            aliases: ['bandwidth-bi-threshold-negate']
            type: str
            description: Negate bi-bandwidth threshold.
            choices: ['disable', 'enable']
          bandwidth_down_threshold_negate:
            aliases: ['bandwidth-down-threshold-negate']
            type: str
            description: Negate down bandwidth threshold.
            choices: ['disable', 'enable']
          bandwidth_up_threshold_negate:
            aliases: ['bandwidth-up-threshold-negate']
            type: str
            description: Negate up bandwidth threshold.
            choices: ['disable', 'enable']
          latency_threshold_negate:
            aliases: ['latency-threshold-negate']
            type: str
            description: Negate latency threshold.
            choices: ['disable', 'enable']
          packet_loss_threshold_negate:
            aliases: ['packet-loss-threshold-negate']
            type: str
            description: Negate packet loss threshold.
            choices: ['disable', 'enable']
          tos:
            type: list
            elements: dict
            description: Tos.
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
      name:
        type: str
        description: Profile name.
        required: true
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
        '/pm/config/adom/{adom}/obj/vpn/ipsec/fec',
        '/pm/config/global/obj/vpn/ipsec/fec'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpn_ipsec_fec': {
            'type': 'dict', 'v_range': [['7.2.0', '']],
            'options': {
                'mappings': {
                    'v_range': [['7.2.0', '']],
                    'type': 'list',
                    'options': {
                        'bandwidth-bi-threshold': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'bandwidth-down-threshold': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'bandwidth-up-threshold': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'base': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'latency-threshold': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'packet-loss-threshold': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'redundant': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'seqno': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'bandwidth-bi-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-down-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-up-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'latency-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'packet-loss-threshold-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tos': {
                            'v_range': [['8.0.0', '']],
                            'type': 'list',
                            'options': {
                                'base': {'v_range': [['8.0.0', '']], 'type': 'int'},
                                'redundant': {'v_range': [['8.0.0', '']], 'type': 'int'},
                                'seqno': {'v_range': [['8.0.0', '']], 'type': 'int'},
                                'tos': {'v_range': [['8.0.0', '']], 'type': 'str'},
                                'tos-mask': {'v_range': [['8.0.0', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.2.0', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_fec'),
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
