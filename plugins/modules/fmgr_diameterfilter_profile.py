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
module: fmgr_diameterfilter_profile
short_description: Configure Diameter filter profiles.
version_added: "2.4.0"
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
    diameterfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cmd_flags_reserve_set:
                aliases: ['cmd-flags-reserve-set']
                type: str
                description: Action to be taken for messages with cmd flag reserve bits set.
                choices: ['block', 'reset', 'monitor', 'allow']
            command_code_invalid:
                aliases: ['command-code-invalid']
                type: str
                description: Action to be taken for messages with invalid command code.
                choices: ['block', 'reset', 'monitor', 'allow']
            command_code_range:
                aliases: ['command-code-range']
                type: str
                description: Valid range for command codes
            comment:
                type: str
                description: Comment.
            log_packet:
                aliases: ['log-packet']
                type: str
                description: Enable/disable packet log for triggered diameter settings.
                choices: ['disable', 'enable']
            message_length_invalid:
                aliases: ['message-length-invalid']
                type: str
                description: Action to be taken for invalid message length.
                choices: ['block', 'reset', 'monitor', 'allow']
            missing_request_action:
                aliases: ['missing-request-action']
                type: str
                description: Action to be taken for answers without corresponding request.
                choices: ['block', 'reset', 'monitor', 'allow']
            monitor_all_messages:
                aliases: ['monitor-all-messages']
                type: str
                description: Enable/disable logging for all User Name and Result Code AVP messages.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Profile name.
                required: true
            protocol_version_invalid:
                aliases: ['protocol-version-invalid']
                type: str
                description: Action to be taken for invalid protocol version.
                choices: ['block', 'reset', 'monitor', 'allow']
            request_error_flag_set:
                aliases: ['request-error-flag-set']
                type: str
                description: Action to be taken for request messages with error flag set.
                choices: ['block', 'reset', 'monitor', 'allow']
            track_requests_answers:
                aliases: ['track-requests-answers']
                type: str
                description: Enable/disable validation that each answer has a corresponding request.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Diameter filter profiles.
      fortinet.fortimanager.fmgr_diameterfilter_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        diameterfilter_profile:
          name: "your value" # Required variable, string
          # cmd_flags_reserve_set: <value in [block, reset, monitor, ...]>
          # command_code_invalid: <value in [block, reset, monitor, ...]>
          # command_code_range: <string>
          # comment: <string>
          # log_packet: <value in [disable, enable]>
          # message_length_invalid: <value in [block, reset, monitor, ...]>
          # missing_request_action: <value in [block, reset, monitor, ...]>
          # monitor_all_messages: <value in [disable, enable]>
          # protocol_version_invalid: <value in [block, reset, monitor, ...]>
          # request_error_flag_set: <value in [block, reset, monitor, ...]>
          # track_requests_answers: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/diameter-filter/profile',
        '/pm/config/global/obj/diameter-filter/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'diameterfilter_profile': {
            'type': 'dict', 'v_range': [['7.4.2', '']],
            'options': {
                'cmd-flags-reserve-set': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'command-code-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'command-code-range': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'comment': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'log-packet': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'message-length-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'missing-request-action': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'monitor-all-messages': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'str'},
                'protocol-version-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'request-error-flag-set': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'track-requests-answers': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'diameterfilter_profile'),
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
