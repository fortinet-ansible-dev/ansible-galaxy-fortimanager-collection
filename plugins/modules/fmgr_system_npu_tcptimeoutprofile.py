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
module: fmgr_system_npu_tcptimeoutprofile
short_description: Configure TCP timeout profile.
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
    system_npu_tcptimeoutprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            close_wait:
                aliases: ['close-wait']
                type: int
                description: Set close-wait timeout
            fin_wait:
                aliases: ['fin-wait']
                type: int
                description: Set fin-wait timeout
            id:
                type: int
                description: Timeout profile ID
                required: true
            syn_sent:
                aliases: ['syn-sent']
                type: int
                description: Set syn-sent timeout
            syn_wait:
                aliases: ['syn-wait']
                type: int
                description: Set syn-wait timeout
            tcp_idle:
                aliases: ['tcp-idle']
                type: int
                description: Set TCP establish timeout
            time_wait:
                aliases: ['time-wait']
                type: int
                description: Set time-wait timeout
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure TCP timeout profile.
      fortinet.fortimanager.fmgr_system_npu_tcptimeoutprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_npu_tcptimeoutprofile:
          id: 0 # Required variable, integer
          # close_wait: <integer>
          # fin_wait: <integer>
          # syn_sent: <integer>
          # syn_wait: <integer>
          # tcp_idle: <integer>
          # time_wait: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/tcp-timeout-profile',
        '/pm/config/global/obj/system/npu/tcp-timeout-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_tcptimeoutprofile': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'close-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'fin-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'required': True, 'type': 'int'},
                'syn-sent': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'syn-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'tcp-idle': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'time-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_tcptimeoutprofile'),
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
