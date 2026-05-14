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
module: fmgr_system_npu_backgroundssescan
short_description: Configure driver background scan for SSE.
version_added: "2.2.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_npu_backgroundssescan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            scan:
                type: str
                description: Enable/disable background SSE scan by driver thread
                choices: ['disable', 'enable']
            stats_update_interval:
                aliases: ['stats-update-interval']
                type: int
                description: Stats update interval
            udp_keepalive_interval:
                aliases: ['udp-keepalive-interval']
                type: int
                description: UDP keepalive interval
            scan_stale:
                aliases: ['scan-stale']
                type: int
                description: Configure scanning of active or stale sessions
            scan_vt:
                aliases: ['scan-vt']
                type: int
                description: Select version/type to scan
            stats_qual_access:
                aliases: ['stats-qual-access']
                type: int
                description: Statistics update access qualification in seconds
            stats_qual_duration:
                aliases: ['stats-qual-duration']
                type: int
                description: Statistics update duration qualification in seconds
            udp_qual_access:
                aliases: ['udp-qual-access']
                type: int
                description: UDP keepalive access qualification in seconds
            udp_qual_duration:
                aliases: ['udp-qual-duration']
                type: int
                description: UDP keepalive duration qualification in seconds
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure driver background scan for SSE.
      fortinet.fortimanager.fmgr_system_npu_backgroundssescan:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        system_npu_backgroundssescan:
          # scan: <value in [disable, enable]>
          # stats_update_interval: <integer>
          # udp_keepalive_interval: <integer>
          # scan_stale: <integer>
          # scan_vt: <integer>
          # stats_qual_access: <integer>
          # stats_qual_duration: <integer>
          # udp_qual_access: <integer>
          # udp_qual_duration: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/background-sse-scan',
        '/pm/config/global/obj/system/npu/background-sse-scan'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_backgroundssescan': {
            'type': 'dict', 'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']],
            'options': {
                'scan': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'stats-update-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'udp-keepalive-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'scan-stale': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'scan-vt': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'stats-qual-access': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'stats-qual-duration': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'udp-qual-access': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'},
                'udp-qual-duration': {'v_range': [['7.0.12', '7.0.16'], ['7.2.6', '7.2.12'], ['7.4.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_backgroundssescan'),
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
