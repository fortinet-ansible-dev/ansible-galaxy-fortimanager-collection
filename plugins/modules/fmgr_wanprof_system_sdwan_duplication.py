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
module: fmgr_wanprof_system_sdwan_duplication
short_description: Create SD-WAN duplication rule.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    wanprof:
        description: The parameter (wanprof) in requested url.
        type: str
        required: true
    wanprof_system_sdwan_duplication:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dstaddr:
                type: raw
                description: (list or str) Destination address or address group names.
            dstaddr6:
                type: raw
                description: (list or str) Destination address6 or address6 group names.
            dstintf:
                type: raw
                description: (list or str) Outgoing
            id:
                type: int
                description: Duplication rule ID
                required: true
            packet_de_duplication:
                aliases: ['packet-de-duplication']
                type: str
                description: Enable/disable discarding of packets that have been duplicated.
                choices: ['disable', 'enable']
            packet_duplication:
                aliases: ['packet-duplication']
                type: str
                description: Configure packet duplication method.
                choices: ['disable', 'force', 'on-demand']
            service:
                type: raw
                description: (list or str) Service and service group name.
            srcaddr:
                type: raw
                description: (list or str) Source address or address group names.
            srcaddr6:
                type: raw
                description: (list or str) Source address6 or address6 group names.
            srcintf:
                type: raw
                description: (list or str) Incoming
            service_id:
                aliases: ['service-id']
                type: raw
                description: (list or str) SD-WAN service rule ID list.
            sla_match_service:
                aliases: ['sla-match-service']
                type: str
                description: Enable/disable packet duplication matching health-check SLAs in service rule.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create SD-WAN duplication rule.
      fortinet.fortimanager.fmgr_wanprof_system_sdwan_duplication:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        wanprof: <your own value>
        state: present # <value in [present, absent]>
        wanprof_system_sdwan_duplication:
          id: 0 # Required variable, integer
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # dstintf: <list or string>
          # packet_de_duplication: <value in [disable, enable]>
          # packet_duplication: <value in [disable, force, on-demand]>
          # service: <list or string>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # srcintf: <list or string>
          # service_id: <list or string>
          # sla_match_service: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'wanprof_system_sdwan_duplication': {
            'type': 'dict', 'v_range': [['6.4.2', '']],
            'options': {
                'dstaddr': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'dstaddr6': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'dstintf': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'id': {'v_range': [['6.4.2', '']], 'required': True, 'type': 'int'},
                'packet-de-duplication': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'packet-duplication': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'force', 'on-demand'], 'type': 'str'},
                'service': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'srcaddr': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'srcaddr6': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'srcintf': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'service-id': {'v_range': [['6.4.3', '']], 'type': 'raw'},
                'sla-match-service': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan_duplication'),
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
