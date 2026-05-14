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
module: fmgr_switchcontroller_macpolicy
short_description: Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
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
    switchcontroller_macpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bounce_port_link:
                aliases: ['bounce-port-link']
                type: str
                description: Enable/disable bouncing
                choices: ['disable', 'enable']
            count:
                type: str
                description: Enable/disable packet count on the NAC device.
                choices: ['disable', 'enable']
            description:
                type: str
                description: Description for the MAC policy.
            name:
                type: str
                description: MAC policy name.
                required: true
            traffic_policy:
                aliases: ['traffic-policy']
                type: str
                description: Traffic policy to be applied when using this MAC policy.
            vlan:
                type: str
                description: Ingress traffic VLAN assignment for the MAC address matching this MAC policy.
            drop:
                type: str
                description: Drop.
                choices: ['disable', 'enable']
            fortilink:
                type: raw
                description: (list) FortiLink interface for which this MAC policy belongs to.
            bounce_port_duration:
                aliases: ['bounce-port-duration']
                type: int
                description: Bounce duration in seconds of a switch port where this mac-policy is applied.
            poe_reset:
                aliases: ['poe-reset']
                type: str
                description: Enable/disable POE reset of a switch port where this mac-policy is applied.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
      fortinet.fortimanager.fmgr_switchcontroller_macpolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_macpolicy:
          name: "your value" # Required variable, string
          # bounce_port_link: <value in [disable, enable]>
          # count: <value in [disable, enable]>
          # description: <string>
          # traffic_policy: <string>
          # vlan: <string>
          # drop: <value in [disable, enable]>
          # fortilink: <list or string>
          # bounce_port_duration: <integer>
          # poe_reset: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/mac-policy',
        '/pm/config/global/obj/switch-controller/mac-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_macpolicy': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'bounce-port-link': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'count': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'description': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'traffic-policy': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'vlan': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'drop': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortilink': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'bounce-port-duration': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'poe-reset': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_macpolicy'),
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
