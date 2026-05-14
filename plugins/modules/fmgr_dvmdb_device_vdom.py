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
module: fmgr_dvmdb_device_vdom
short_description: Device VDOM table.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    dvmdb_device_vdom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comments.
            name:
                type: str
                description: Name.
                required: true
            opmode:
                type: str
                description: Opmode.
                choices: ['nat', 'transparent']
            rtm_prof_id:
                type: int
                description: Rtm prof id.
            status:
                type: str
                description: Status.
            vpn_id:
                type: int
                description: Vpn id.
            meta_fields:
                aliases: ['meta fields']
                type: dict
                description: Meta fields.
            vdom_type:
                type: str
                description: Vdom type.
                choices: ['traffic', 'admin']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device VDOM table.
      fortinet.fortimanager.fmgr_dvmdb_device_vdom:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        device: <your own value>
        state: present # <value in [present, absent]>
        dvmdb_device_vdom:
          name: "your value" # Required variable, string
          # comments: <string>
          # opmode: <value in [nat, transparent]>
          # rtm_prof_id: <integer>
          # status: <string>
          # vpn_id: <integer>
          # meta_fields: <dict>
          # vdom_type: <value in [traffic, admin]>
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
        '/dvmdb/adom/{adom}/device/{device}/vdom',
        '/dvmdb/device/{device}/vdom'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device': {'required': True, 'type': 'str'},
        'dvmdb_device_vdom': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comments': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'opmode': {'choices': ['nat', 'transparent'], 'type': 'str'},
                'rtm_prof_id': {'type': 'int'},
                'status': {'type': 'str'},
                'vpn_id': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'meta fields': {'v_range': [['6.4.3', '']], 'type': 'dict'},
                'vdom_type': {'v_range': [['7.2.0', '']], 'choices': ['traffic', 'admin'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_device_vdom'),
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
