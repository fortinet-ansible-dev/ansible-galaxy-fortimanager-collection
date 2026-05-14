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
module: fmgr_system_log_devicedisable
short_description: Disable client device logging.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_log_devicedisable:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            TTL:
                type: str
                description: Time to Live
            device:
                type: str
                description: Device to be disabled logging
            id:
                type: int
                description: ID of device logging disable entry.
                required: true
            expire:
                type: str
                description: Expire.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Disable client device logging.
      fortinet.fortimanager.fmgr_system_log_devicedisable:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_log_devicedisable:
          id: 0 # Required variable, integer
          # TTL: <string>
          # device: <string>
          # expire: <string>
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
        '/cli/global/system/log/device-disable'
    ]
    module_arg_spec = {
        'system_log_devicedisable': {
            'type': 'dict', 'v_range': [['6.4.4', '7.4.6'], ['7.6.0', '7.6.2']],
            'options': {
                'TTL': {'v_range': [['6.4.4', '7.4.6'], ['7.6.0', '7.6.1']], 'type': 'str'},
                'device': {'v_range': [['6.4.4', '7.4.6'], ['7.6.0', '7.6.2']], 'type': 'str'},
                'id': {'v_range': [['6.4.4', '7.4.6'], ['7.6.0', '7.6.2']], 'required': True, 'type': 'int'},
                'expire': {'v_range': [['7.6.2', '7.6.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_devicedisable'),
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
