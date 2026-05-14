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
module: fmgr_fsp_vlan_interface_vrrp
short_description: VRRP configuration.
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    fsp_vlan_interface_vrrp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accept_mode:
                aliases: ['accept-mode']
                type: str
                description: Accept mode.
                choices: ['disable', 'enable']
            adv_interval:
                aliases: ['adv-interval']
                type: int
                description: Adv interval.
            ignore_default_route:
                aliases: ['ignore-default-route']
                type: str
                description: Ignore default route.
                choices: ['disable', 'enable']
            preempt:
                type: str
                description: Preempt.
                choices: ['disable', 'enable']
            priority:
                type: int
                description: Priority.
            start_time:
                aliases: ['start-time']
                type: int
                description: Start time.
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            version:
                type: str
                description: Version.
                choices: ['2', '3']
            vrdst:
                type: raw
                description: (list) Vrdst.
            vrdst_priority:
                aliases: ['vrdst-priority']
                type: int
                description: Vrdst priority.
            vrgrp:
                type: int
                description: Vrgrp.
            vrid:
                type: int
                description: Vrid.
                required: true
            vrip:
                type: str
                description: Vrip.
            proxy_arp:
                aliases: ['proxy-arp']
                type: list
                elements: dict
                description: Proxy arp.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: str
                        description: Set IP addresses of proxy ARP.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: VRRP configuration.
      fortinet.fortimanager.fmgr_fsp_vlan_interface_vrrp:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vlan: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_interface_vrrp:
          vrid: 0 # Required variable, integer
          # accept_mode: <value in [disable, enable]>
          # adv_interval: <integer>
          # ignore_default_route: <value in [disable, enable]>
          # preempt: <value in [disable, enable]>
          # priority: <integer>
          # start_time: <integer>
          # status: <value in [disable, enable]>
          # version: <value in [2, 3]>
          # vrdst: <list or string>
          # vrdst_priority: <integer>
          # vrgrp: <integer>
          # vrip: <string>
          # proxy_arp:
          #   - id: <integer>
          #     ip: <string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp',
        '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_interface_vrrp': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'accept-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'adv-interval': {'type': 'int'},
                'ignore-default-route': {'choices': ['disable', 'enable'], 'type': 'str'},
                'preempt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'type': 'int'},
                'start-time': {'type': 'int'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'version': {'choices': ['2', '3'], 'type': 'str'},
                'vrdst': {'type': 'raw'},
                'vrdst-priority': {'type': 'int'},
                'vrgrp': {'type': 'int'},
                'vrid': {'required': True, 'type': 'int'},
                'vrip': {'type': 'str'},
                'proxy-arp': {
                    'v_range': [['7.4.0', '']],
                    'type': 'list',
                    'options': {'id': {'v_range': [['7.4.0', '']], 'type': 'int'}, 'ip': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_interface_vrrp'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'vrid', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
