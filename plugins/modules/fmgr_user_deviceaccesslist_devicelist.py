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
module: fmgr_user_deviceaccesslist_devicelist
short_description: Device list.
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
    device-access-list:
        description: Deprecated, please use "device_access_list"
        type: str
    device_access_list:
        description: The parameter (device-access-list) in requested url.
        type: str
    user_deviceaccesslist_devicelist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Allow or block device.
                choices: ['deny', 'accept']
            device:
                type: str
                description: Firewall device or device group.
            id:
                type: int
                description: Entry ID.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device list.
      fortinet.fortimanager.fmgr_user_deviceaccesslist_devicelist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        device_access_list: <your own value>
        state: present # <value in [present, absent]>
        user_deviceaccesslist_devicelist:
          id: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # device: <string>
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
        '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list',
        '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device-access-list': {'type': 'str', 'api_name': 'device_access_list'},
        'device_access_list': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_deviceaccesslist_devicelist': {
            'type': 'dict', 'v_range': [['6.2.2', '7.2.1']],
            'options': {
                'action': {'v_range': [['6.2.2', '7.2.1']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'device': {'v_range': [['6.2.2', '7.2.1']], 'type': 'str'},
                'id': {'v_range': [['6.2.2', '7.2.1']], 'required': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_deviceaccesslist_devicelist'),
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
