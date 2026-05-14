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
module: fmgr_pkg_firewall_policy46
short_description: Configure IPv4 to IPv6 policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_policy46:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Accept or deny traffic matching the policy.
                choices: ['deny', 'accept']
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list or str) Destination address objects.
            dstintf:
                type: str
                description: Destination interface name.
            fixedport:
                type: str
                description: Enable/disable fixed port for this policy.
                choices: ['disable', 'enable']
            logtraffic:
                type: str
                description: Enable/disable traffic logging for this policy.
                choices: ['disable', 'enable']
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: str
                description: Per IP traffic shaper.
            permit_any_host:
                aliases: ['permit-any-host']
                type: str
                description: Enable/disable allowing any host.
                choices: ['disable', 'enable']
            policyid:
                type: int
                description: Policy ID.
                required: true
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service name.
            srcaddr:
                type: raw
                description: (list or str) Source address objects.
            srcintf:
                type: str
                description: Source interface name.
            status:
                type: str
                description: Enable/disable this policy.
                choices: ['disable', 'enable']
            tags:
                type: str
                description: Applied object tags.
            tcp_mss_receiver:
                aliases: ['tcp-mss-receiver']
                type: int
                description: TCP Maximum Segment Size value of receiver
            tcp_mss_sender:
                aliases: ['tcp-mss-sender']
                type: int
                description: TCP Maximum Segment Size value of sender
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Reverse traffic shaper.
            uuid:
                type: str
                description: Universally Unique Identifier
            ippool:
                type: str
                description: Enable/disable use of IP Pools for source NAT.
                choices: ['disable', 'enable']
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Record logs when a session starts and ends.
                choices: ['disable', 'enable']
            poolname:
                type: raw
                description: (list or str) IP Pool names.
            name:
                type: str
                description: Policy name.
            cgn_log_server_grp:
                aliases: ['cgn-log-server-grp']
                type: str
                description: NP log server group name
            policy_offload:
                aliases: ['policy-offload']
                type: str
                description: Enable/disable hardware session setup for CGNAT.
                choices: ['disable', 'enable']
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
    - name: Configure IPv4 to IPv6 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_policy46:
        bypass_validation: true
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_policy46:
          action: accept # <value in [deny, accept]>
          comments: ansible-comment
          dstaddr: ansible-test-vip46
          dstintf: any
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
          srcintf: any
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 to IPv6 policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_policy46"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            policy46: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_policy46': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'comments': {'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstintf': {'type': 'str'},
                'fixedport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'schedule': {'type': 'str'},
                'service': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcintf': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'tcp-mss-receiver': {'type': 'int'},
                'tcp-mss-sender': {'type': 'int'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'uuid': {'type': 'str'},
                'ippool': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'poolname': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.6.2']], 'type': 'str'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy46'),
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
