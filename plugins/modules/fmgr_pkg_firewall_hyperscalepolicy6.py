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
module: fmgr_pkg_firewall_hyperscalepolicy6
short_description: Configure IPv6 policies.
version_added: "2.2.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_hyperscalepolicy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices: ['deny', 'accept', 'ipsec']
            auto_asic_offload:
                aliases: ['auto-asic-offload']
                type: str
                description: Enable/disable policy traffic ASIC offloading.
                choices: ['disable', 'enable']
            cgn_log_server_grp:
                aliases: ['cgn-log-server-grp']
                type: str
                description: NP log server group name
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) Destination address and address group names.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices: ['disable', 'enable']
            dstintf:
                type: raw
                description: (list or str) Outgoing
            name:
                type: str
                description: Policy name.
            policy_offload:
                aliases: ['policy-offload']
                type: str
                description: Enable/disable offloading policy configuration to CP processors.
                choices: ['disable', 'enable']
            policyid:
                type: int
                description: Policy ID
                required: true
            service:
                type: raw
                description: (list or str) Service and service group names.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices: ['disable', 'enable']
            srcaddr:
                type: raw
                description: (list or str) Source address and address group names.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices: ['disable', 'enable']
            srcintf:
                type: raw
                description: (list or str) Incoming
            status:
                type: str
                description: Enable or disable this policy.
                choices: ['disable', 'enable']
            tcp_timeout_pid:
                aliases: ['tcp-timeout-pid']
                type: str
                description: TCP timeout profile ID
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Reverse traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Reverse traffic shaper.
            udp_timeout_pid:
                aliases: ['udp-timeout-pid']
                type: str
                description: UDP timeout profile ID
            uuid:
                type: str
                description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy6:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_hyperscalepolicy6:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept, ipsec]>
          # auto_asic_offload: <value in [disable, enable]>
          # cgn_log_server_grp: <string>
          # comments: <string>
          # dstaddr: <list or string>
          # dstaddr_negate: <value in [disable, enable]>
          # dstintf: <list or string>
          # name: <string>
          # policy_offload: <value in [disable, enable]>
          # service: <list or string>
          # service_negate: <value in [disable, enable]>
          # srcaddr: <list or string>
          # srcaddr_negate: <value in [disable, enable]>
          # srcintf: <list or string>
          # status: <value in [disable, enable]>
          # tcp_timeout_pid: <string>
          # traffic_shaper: <string>
          # traffic_shaper_reverse: <string>
          # udp_timeout_pid: <string>
          # uuid: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_hyperscalepolicy6': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
            'options': {
                'action': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['deny', 'accept', 'ipsec'],
                    'type': 'str'
                },
                'auto-asic-offload': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'cgn-log-server-grp': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'comments': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'dstaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'raw'},
                'dstaddr-negate': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dstintf': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'raw'},
                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'policy-offload': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'policyid': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'required': True,
                    'type': 'int'
                },
                'service': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'raw'},
                'service-negate': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'srcaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'raw'},
                'srcaddr-negate': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'srcintf': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'raw'},
                'status': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'tcp-timeout-pid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'traffic-shaper': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'traffic-shaper-reverse': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'udp-timeout-pid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'uuid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_hyperscalepolicy6'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
