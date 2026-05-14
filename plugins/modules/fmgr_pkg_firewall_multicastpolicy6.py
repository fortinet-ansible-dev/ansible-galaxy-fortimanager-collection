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
module: fmgr_pkg_firewall_multicastpolicy6
short_description: Configure IPv6 multicast NAT policies.
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
    pkg_firewall_multicastpolicy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Accept or deny traffic matching the policy.
                choices: ['deny', 'accept']
            auto_asic_offload:
                aliases: ['auto-asic-offload']
                type: str
                description: Enable/disable offloading policy traffic for hardware acceleration.
                choices: ['disable', 'enable']
            dstaddr:
                type: raw
                description: (list or str) IPv6 destination address name.
            dstintf:
                type: str
                description: IPv6 destination interface name.
            end_port:
                aliases: ['end-port']
                type: int
                description: Integer value for ending TCP/UDP/SCTP destination port in range
            id:
                type: int
                description: Policy ID.
                required: true
            logtraffic:
                type: str
                description: Enable/disable logging traffic accepted by this policy.
                choices: ['disable', 'enable', 'all', 'utm']
            protocol:
                type: int
                description: Integer value for the protocol type as defined by IANA
            srcaddr:
                type: raw
                description: (list or str) IPv6 source address name.
            srcintf:
                type: str
                description: IPv6 source interface name.
            start_port:
                aliases: ['start-port']
                type: int
                description: Integer value for starting TCP/UDP/SCTP destination port in range
            status:
                type: str
                description: Enable/disable this policy.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Policy name.
            comments:
                type: str
                description: Comment.
            uuid:
                type: str
                description: Universally Unique Identifier
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: Name of an existing IPS sensor.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable to add an IPS security profile to the policy.
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
    - name: Configure IPv6 multicast NAT policies.
      fortinet.fortimanager.fmgr_pkg_firewall_multicastpolicy6:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_multicastpolicy6:
          action: accept # <value in [deny, accept]>
          auto_asic_offload: enable
          dstaddr: all
          dstintf: any
          id: 1
          logtraffic: enable
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
    - name: Retrieve all the IPv6 multicast NAT policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_multicastpolicy6"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            multicast_policy6: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_multicastpolicy6': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept'], 'type': 'str'},
                'auto-asic-offload': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dstaddr': {'type': 'raw'},
                'dstintf': {'type': 'str'},
                'end-port': {'type': 'int'},
                'id': {'required': True, 'type': 'int'},
                'logtraffic': {'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'protocol': {'type': 'int'},
                'srcaddr': {'type': 'raw'},
                'srcintf': {'type': 'str'},
                'start-port': {'type': 'int'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'comments': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'uuid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'ips-sensor': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'utm-status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_multicastpolicy6'),
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
