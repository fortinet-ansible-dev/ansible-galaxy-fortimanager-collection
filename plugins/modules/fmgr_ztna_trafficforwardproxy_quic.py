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
module: fmgr_ztna_trafficforwardproxy_quic
short_description: Ztna traffic forward proxy quic
version_added: "2.14.0"
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
    traffic-forward-proxy:
        description: Deprecated, please use "traffic_forward_proxy"
        type: str
    traffic_forward_proxy:
        description: The parameter (traffic-forward-proxy) in requested url.
        type: str
    ztna_trafficforwardproxy_quic:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ack_delay_exponent:
                aliases: ['ack-delay-exponent']
                type: int
                description: Ack delay exponent.
            active_connection_id_limit:
                aliases: ['active-connection-id-limit']
                type: int
                description: Active connection id limit.
            active_migration:
                aliases: ['active-migration']
                type: str
                description: Active migration.
                choices: ['disable', 'enable']
            grease_quic_bit:
                aliases: ['grease-quic-bit']
                type: str
                description: Grease quic bit.
                choices: ['disable', 'enable']
            max_ack_delay:
                aliases: ['max-ack-delay']
                type: int
                description: Max ack delay.
            max_datagram_frame_size:
                aliases: ['max-datagram-frame-size']
                type: int
                description: Max datagram frame size.
            max_idle_timeout:
                aliases: ['max-idle-timeout']
                type: int
                description: Max idle timeout.
            max_udp_payload_size:
                aliases: ['max-udp-payload-size']
                type: int
                description: Max udp payload size.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Ztna traffic forward proxy quic
      fortinet.fortimanager.fmgr_ztna_trafficforwardproxy_quic:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        traffic_forward_proxy: <your own value>
        ztna_trafficforwardproxy_quic:
          # ack_delay_exponent: <integer>
          # active_connection_id_limit: <integer>
          # active_migration: <value in [disable, enable]>
          # grease_quic_bit: <value in [disable, enable]>
          # max_ack_delay: <integer>
          # max_datagram_frame_size: <integer>
          # max_idle_timeout: <integer>
          # max_udp_payload_size: <integer>
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
        '/pm/config/adom/{adom}/obj/ztna/traffic-forward-proxy/{traffic-forward-proxy}/quic',
        '/pm/config/global/obj/ztna/traffic-forward-proxy/{traffic-forward-proxy}/quic'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'traffic-forward-proxy': {'type': 'str', 'api_name': 'traffic_forward_proxy'},
        'traffic_forward_proxy': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_trafficforwardproxy_quic': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'ack-delay-exponent': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'active-connection-id-limit': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'active-migration': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'grease-quic-bit': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-ack-delay': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'max-datagram-frame-size': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'max-idle-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'max-udp-payload-size': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_trafficforwardproxy_quic'),
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
