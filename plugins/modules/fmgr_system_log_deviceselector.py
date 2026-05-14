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
module: fmgr_system_log_deviceselector
short_description: Accept/reject devices matching specified filter types.
version_added: "2.10.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_log_deviceselector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description:
                    - Include or exclude the matching devices.
                    - include - Include devices matching specified filter type.
                    - exclude - Exclude devices matching specified filter type.
                choices: ['include', 'exclude']
            comment:
                type: str
                description: Additional comment for the selector.
            devid:
                type: str
                description: Device ID.
            expire:
                type: str
                description: Expiration time of the selector.
            id:
                type: int
                description: ID of device selector entry.
                required: true
            srcip:
                type: str
                description: Source IP or IP range.
            srcip_mode:
                aliases: ['srcip-mode']
                type: str
                description:
                    - Apply the selector to UDP/514, TCP/514 or any mode.
                    - UDP514 - Clients logging through UDP port 514.
                    - TCP514 - Clients logging through TCP port 514.
                    - any - Clients logging through any mode.
                choices: ['UDP514', 'TCP514', 'any']
            type:
                type: str
                description:
                    - Type of the selector.
                    - unspecified - Filter type unspecified.
                    - devid - Filter devices by DeviceID.
                    - srcip - Filter devices by source IP.
                choices: ['unspecified', 'devid', 'srcip']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Accept/reject devices matching specified filter types.
      fortinet.fortimanager.fmgr_system_log_deviceselector:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_log_deviceselector:
          id: 0 # Required variable, integer
          # action: <value in [include, exclude]>
          # comment: <string>
          # devid: <string>
          # expire: <string>
          # srcip: <string>
          # srcip_mode: <value in [UDP514, TCP514, any]>
          # type: <value in [unspecified, devid, srcip]>
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
        '/cli/global/system/log/device-selector'
    ]
    module_arg_spec = {
        'system_log_deviceselector': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']],
            'options': {
                'action': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'comment': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'str'},
                'devid': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'str'},
                'expire': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'required': True, 'type': 'int'},
                'srcip': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'str'},
                'srcip-mode': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'choices': ['UDP514', 'TCP514', 'any'], 'type': 'str'},
                'type': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'choices': ['unspecified', 'devid', 'srcip'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_deviceselector'),
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
