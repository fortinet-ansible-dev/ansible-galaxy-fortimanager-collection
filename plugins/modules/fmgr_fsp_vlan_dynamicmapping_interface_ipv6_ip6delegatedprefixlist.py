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
module: fmgr_fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist
short_description: Advertised IPv6 delegated prefix list.
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            autonomous_flag:
                aliases: ['autonomous-flag']
                type: str
                description: Autonomous flag.
                choices: ['disable', 'enable']
            onlink_flag:
                aliases: ['onlink-flag']
                type: str
                description: Onlink flag.
                choices: ['disable', 'enable']
            prefix_id:
                aliases: ['prefix-id']
                type: int
                description: Prefix id.
            rdnss:
                type: raw
                description: (list) Rdnss.
            rdnss_service:
                aliases: ['rdnss-service']
                type: str
                description: Rdnss service.
                choices: ['delegated', 'default', 'specify']
            subnet:
                type: str
                description: Subnet.
            upstream_interface:
                aliases: ['upstream-interface']
                type: str
                description: Upstream interface.
            delegated_prefix_iaid:
                aliases: ['delegated-prefix-iaid']
                type: int
                description: IAID of obtained delegated-prefix from the upstream interface.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Advertised IPv6 delegated prefix list.
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vlan: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist:
          # autonomous_flag: <value in [disable, enable]>
          # onlink_flag: <value in [disable, enable]>
          # prefix_id: <integer>
          # rdnss: <list or string>
          # rdnss_service: <value in [delegated, default, specify]>
          # subnet: <string>
          # upstream_interface: <string>
          # delegated_prefix_iaid: <integer>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist': {
            'type': 'dict', 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'autonomous-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'onlink-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prefix-id': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'rdnss': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                'rdnss-service': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['delegated', 'default', 'specify'], 'type': 'str'},
                'subnet': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'upstream-interface': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'delegated-prefix-iaid': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist'),
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
