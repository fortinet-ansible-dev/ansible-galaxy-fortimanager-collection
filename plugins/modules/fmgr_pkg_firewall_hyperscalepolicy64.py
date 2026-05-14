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
module: fmgr_pkg_firewall_hyperscalepolicy64
short_description: Configure IPv6 to IPv4 policies.
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
    pkg_firewall_hyperscalepolicy64:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action.
                choices: ['deny', 'accept']
            cgn_eif:
                aliases: ['cgn-eif']
                type: str
                description: Enable/disable CGN endpoint independent filtering.
                choices: ['disable', 'enable']
            cgn_eim:
                aliases: ['cgn-eim']
                type: str
                description: Enable/disable CGN endpoint independent mapping.
                choices: ['disable', 'enable']
            cgn_log_server_grp:
                aliases: ['cgn-log-server-grp']
                type: str
                description: NP log server group name
            cgn_resource_quota:
                aliases: ['cgn-resource-quota']
                type: int
                description: Resource quota
            cgn_session_quota:
                aliases: ['cgn-session-quota']
                type: int
                description: Session quota
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) Destination address name.
            dstintf:
                type: str
                description: Destination interface name.
            ippool:
                type: str
                description: Enable/disable policy64 IP pool.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Policy name.
            policy_offload:
                aliases: ['policy-offload']
                type: str
                description: Enable/disable hardware session setup for CGNAT.
                choices: ['disable', 'enable']
            policyid:
                type: int
                description: Policy ID
                required: true
            poolname:
                type: raw
                description: (list or str) Policy IP pool names.
            service:
                type: raw
                description: (list or str) Service name.
            srcaddr:
                type: raw
                description: (list or str) Source address name.
            srcintf:
                type: str
                description: Source interface name.
            status:
                type: str
                description: Enable/disable policy status.
                choices: ['disable', 'enable']
            tcp_timeout_pid:
                aliases: ['tcp-timeout-pid']
                type: str
                description: TCP timeout profile ID
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Traffic shaper.
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
    - name: Configure IPv6 to IPv4 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy64:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_hyperscalepolicy64:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # cgn_eif: <value in [disable, enable]>
          # cgn_eim: <value in [disable, enable]>
          # cgn_log_server_grp: <string>
          # cgn_resource_quota: <integer>
          # cgn_session_quota: <integer>
          # comments: <string>
          # dstaddr: <list or string>
          # dstintf: <string>
          # ippool: <value in [disable, enable]>
          # name: <string>
          # policy_offload: <value in [disable, enable]>
          # poolname: <list or string>
          # service: <list or string>
          # srcaddr: <list or string>
          # srcintf: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_hyperscalepolicy64': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'action': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['deny', 'accept'],
                    'type': 'str'
                },
                'cgn-eif': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'cgn-eim': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'cgn-log-server-grp': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'cgn-resource-quota': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'cgn-session-quota': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'comments': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'dstintf': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ippool': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'name': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'policy-offload': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'policyid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'poolname': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'service': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'srcaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'srcintf': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'status': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'tcp-timeout-pid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'traffic-shaper': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'traffic-shaper-reverse': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'udp-timeout-pid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'uuid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_hyperscalepolicy64'),
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
