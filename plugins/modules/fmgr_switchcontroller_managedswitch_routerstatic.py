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
module: fmgr_switchcontroller_managedswitch_routerstatic
short_description: Configure static routes.
version_added: "2.12.0"
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
    managed-switch:
        description: Deprecated, please use "managed_switch"
        type: str
    managed_switch:
        description: The parameter (managed-switch) in requested url.
        type: str
    switchcontroller_managedswitch_routerstatic:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            blackhole:
                type: str
                description: Enable/disable blackhole on this route.
                choices: ['disable', 'enable']
            comment:
                type: str
                description: Comment.
            device:
                type: list
                elements: str
                description: Gateway out interface.
            distance:
                type: int
                description: Administrative distance for the route
            dst:
                type: list
                elements: str
                description: Destination ip and mask for this route.
            dynamic_gateway:
                aliases: ['dynamic-gateway']
                type: str
                description: Enable/disable dynamic gateway.
                choices: ['disable', 'enable']
            gateway:
                type: str
                description: Gateway ip for this route.
            id:
                type: int
                description: Entry sequence number.
                required: true
            status:
                type: str
                description: Enable/disable route status.
                choices: ['disable', 'enable']
            switch_id:
                aliases: ['switch-id']
                type: list
                elements: str
                description: Switch ID.
            vrf:
                type: list
                elements: str
                description: VRF for this route.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure static routes.
      fortinet.fortimanager.fmgr_switchcontroller_managedswitch_routerstatic:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        managed_switch: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_routerstatic:
          id: 0 # Required variable, integer
          # blackhole: <value in [disable, enable]>
          # comment: <string>
          # device: <list or string>
          # distance: <integer>
          # dst: <list or string>
          # dynamic_gateway: <value in [disable, enable]>
          # gateway: <string>
          # status: <value in [disable, enable]>
          # switch_id: <list or string>
          # vrf: <list or string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/router-static'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_managedswitch_routerstatic': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'blackhole': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'device': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'distance': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'dst': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dynamic-gateway': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gateway': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'int'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-id': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vrf': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_routerstatic'),
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
