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
module: fmgr_system_log_ratelimit
short_description: Logging rate limit.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_log_ratelimit:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            device:
                type: list
                elements: dict
                description: Device.
                suboptions:
                    device:
                        type: str
                        description: Device
                    filter_type:
                        aliases: ['filter-type']
                        type: str
                        description:
                            - Device filter type.
                            - devid - Device ID.
                        choices: ['devid']
                    id:
                        type: int
                        description: Device filter ID.
                    ratelimit:
                        type: int
                        description: Maximum device log rate limit.
            device_ratelimit_default:
                aliases: ['device-ratelimit-default']
                type: int
                description: Default maximum device log rate limit.
            mode:
                type: str
                description:
                    - Logging rate limit mode.
                    - disable - Logging rate limit function disabled.
                    - manual - System rate limit and device rate limit both configurable, no limit if not configured.
                choices: ['disable', 'manual']
            system_ratelimit:
                aliases: ['system-ratelimit']
                type: int
                description: Maximum system log rate limit.
            ratelimits:
                type: list
                elements: dict
                description: Ratelimits.
                suboptions:
                    filter:
                        type: str
                        description: Device or ADOM filter according to filter-type setting, wildcard expression supported.
                    filter_type:
                        aliases: ['filter-type']
                        type: str
                        description:
                            - Device filter type.
                            - devid - Device ID.
                            - adom - ADOM name.
                        choices: ['devid', 'adom']
                    id:
                        type: int
                        description: Filter ID.
                    ratelimit:
                        type: int
                        description: Maximum log rate limit.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Logging rate limit.
      fortinet.fortimanager.fmgr_system_log_ratelimit:
        # workspace_locking_adom: <global or your adom name>
        system_log_ratelimit:
          # device:
          #   - device: <string>
          #     filter_type: <value in [devid]>
          #     id: <integer>
          #     ratelimit: <integer>
          # device_ratelimit_default: <integer>
          # mode: <value in [disable, manual]>
          # system_ratelimit: <integer>
          # ratelimits:
          #   - filter: <string>
          #     filter_type: <value in [devid, adom]>
          #     id: <integer>
          #     ratelimit: <integer>
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
        '/cli/global/system/log/ratelimit'
    ]
    module_arg_spec = {
        'system_log_ratelimit': {
            'type': 'dict', 'v_range': [['6.4.8', '']],
            'options': {
                'device': {
                    'v_range': [['6.4.8', '7.0.2']],
                    'type': 'list',
                    'options': {
                        'device': {'v_range': [['6.4.8', '7.0.2']], 'type': 'str'},
                        'filter-type': {'v_range': [['6.4.8', '7.0.2']], 'choices': ['devid'], 'type': 'str'},
                        'id': {'v_range': [['6.4.8', '7.0.2']], 'type': 'int'},
                        'ratelimit': {'v_range': [['6.4.8', '7.0.2']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'device-ratelimit-default': {'v_range': [['6.4.8', '']], 'type': 'int'},
                'mode': {'v_range': [['6.4.8', '']], 'choices': ['disable', 'manual'], 'type': 'str'},
                'system-ratelimit': {'v_range': [['6.4.8', '']], 'type': 'int'},
                'ratelimits': {
                    'v_range': [['7.0.3', '']],
                    'type': 'list',
                    'options': {
                        'filter': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'filter-type': {'v_range': [['7.0.3', '']], 'choices': ['devid', 'adom'], 'type': 'str'},
                        'id': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'ratelimit': {'v_range': [['7.0.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_ratelimit'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
