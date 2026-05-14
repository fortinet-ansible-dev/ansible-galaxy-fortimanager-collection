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
module: fmgr_firewall_shaper_peripshaper
short_description: Configure per-IP traffic shaper.
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
    firewall_shaper_peripshaper:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bandwidth_unit:
                aliases: ['bandwidth-unit']
                type: str
                description: Unit of measurement for maximum bandwidth for this shaper
                choices: ['kbps', 'mbps', 'gbps']
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Enable/disable changing the Forward
                choices: ['disable', 'enable']
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Enable/disable changing the Reverse
                choices: ['disable', 'enable']
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Forward
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Reverse
            max_bandwidth:
                aliases: ['max-bandwidth']
                type: int
                description: Upper bandwidth limit enforced by this shaper
            max_concurrent_session:
                aliases: ['max-concurrent-session']
                type: int
                description: Maximum number of concurrent sessions allowed by this shaper
            name:
                type: str
                description: Traffic shaper name.
                required: true
            max_concurrent_tcp_session:
                aliases: ['max-concurrent-tcp-session']
                type: int
                description: Maximum number of concurrent TCP sessions allowed by this shaper
            max_concurrent_udp_session:
                aliases: ['max-concurrent-udp-session']
                type: int
                description: Maximum number of concurrent UDP sessions allowed by this shaper
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
    - name: Configure per-IP traffic shaper.
      fortinet.fortimanager.fmgr_firewall_shaper_peripshaper:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_shaper_peripshaper:
          bandwidth_unit: mbps # <value in [kbps, mbps, gbps]>
          diffserv_forward: enable
          diffserv_reverse: disable
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the per-IP traffic shapers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_shaper_peripshaper"
          params:
            adom: "ansible"
            per_ip_shaper: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper',
        '/pm/config/global/obj/firewall/shaper/per-ip-shaper'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_shaper_peripshaper': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'bandwidth-unit': {'choices': ['kbps', 'mbps', 'gbps'], 'type': 'str'},
                'diffserv-forward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'type': 'str'},
                'diffservcode-rev': {'type': 'str'},
                'max-bandwidth': {'type': 'int'},
                'max-concurrent-session': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'max-concurrent-tcp-session': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'max-concurrent-udp-session': {'v_range': [['7.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shaper_peripshaper'),
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
