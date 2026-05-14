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
module: fmgr_firewall_mmsprofile_dupe
short_description: Duplicate configuration.
version_added: "2.0.0"
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
    mms-profile:
        description: Deprecated, please use "mms_profile"
        type: str
    mms_profile:
        description: The parameter (mms-profile) in requested url.
        type: str
    firewall_mmsprofile_dupe:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action1:
                type: list
                elements: str
                description: Action to take when threshold reached.
                choices: ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif']
            action2:
                type: list
                elements: str
                description: Action to take when threshold reached.
                choices: ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif']
            action3:
                type: list
                elements: str
                description: Action to take when threshold reached.
                choices: ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif']
            block_time1:
                aliases: ['block-time1']
                type: int
                description: Duration for which action takes effect
            block_time2:
                aliases: ['block-time2']
                type: int
                description: Duration for which action takes effect
            block_time3:
                aliases: ['block-time3']
                type: int
                description: Duration action takes effect
            limit1:
                type: int
                description: Maximum number of messages allowed.
            limit2:
                type: int
                description: Maximum number of messages allowed.
            limit3:
                type: int
                description: Maximum number of messages allowed.
            protocol:
                type: str
                description: Protocol.
            status1:
                type: str
                description: Enable/disable status1 detection.
                choices: ['disable', 'enable']
            status2:
                type: str
                description: Enable/disable status2 detection.
                choices: ['disable', 'enable']
            status3:
                type: str
                description: Enable/disable status3 detection.
                choices: ['disable', 'enable']
            window1:
                type: int
                description: Window to count messages over
            window2:
                type: int
                description: Window to count messages over
            window3:
                type: int
                description: Window to count messages over
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Duplicate configuration.
      fortinet.fortimanager.fmgr_firewall_mmsprofile_dupe:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        mms_profile: <your own value>
        firewall_mmsprofile_dupe:
          # action1: ["log", "archive", "intercept", "block", "archive-first", "alert-notif"]
          # action2: ["log", "archive", "intercept", "block", "archive-first", "alert-notif"]
          # action3: ["log", "archive", "intercept", "block", "archive-first", "alert-notif"]
          # block_time1: <integer>
          # block_time2: <integer>
          # block_time3: <integer>
          # limit1: <integer>
          # limit2: <integer>
          # limit3: <integer>
          # protocol: <string>
          # status1: <value in [disable, enable]>
          # status2: <value in [disable, enable]>
          # status3: <value in [disable, enable]>
          # window1: <integer>
          # window2: <integer>
          # window3: <integer>
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
        '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/dupe',
        '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/dupe'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'mms-profile': {'type': 'str', 'api_name': 'mms_profile'},
        'mms_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_mmsprofile_dupe': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'action1': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                    'elements': 'str'
                },
                'action2': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                    'elements': 'str'
                },
                'action3': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'choices': ['log', 'archive', 'intercept', 'block', 'archive-first', 'alert-notif'],
                    'elements': 'str'
                },
                'block-time1': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'block-time2': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'block-time3': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'limit1': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'limit2': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'limit3': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'protocol': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'status1': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status2': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status3': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'window1': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'window2': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'window3': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_mmsprofile_dupe'),
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
