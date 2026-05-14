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
module: fmgr_extendercontroller_extenderprofile_cellular_smsnotification
short_description: FortiExtender cellular SMS notification configuration.
version_added: "2.1.0"
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
    extender-profile:
        description: Deprecated, please use "extender_profile"
        type: str
    extender_profile:
        description: The parameter (extender-profile) in requested url.
        type: str
    extendercontroller_extenderprofile_cellular_smsnotification:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            alert:
                type: dict
                description: Alert.
                suboptions:
                    data_exhausted:
                        aliases: ['data-exhausted']
                        type: str
                        description: Display string when data exhausted.
                    fgt_backup_mode_switch:
                        aliases: ['fgt-backup-mode-switch']
                        type: str
                        description: Display string when FortiGate backup mode switched.
                    low_signal_strength:
                        aliases: ['low-signal-strength']
                        type: str
                        description: Display string when signal strength is low.
                    mode_switch:
                        aliases: ['mode-switch']
                        type: str
                        description: Display string when mode is switched.
                    os_image_fallback:
                        aliases: ['os-image-fallback']
                        type: str
                        description: Display string when falling back to a previous OS image.
                    session_disconnect:
                        aliases: ['session-disconnect']
                        type: str
                        description: Display string when session disconnected.
                    system_reboot:
                        aliases: ['system-reboot']
                        type: str
                        description: Display string when system rebooted.
            receiver:
                type: list
                elements: dict
                description: Receiver.
                suboptions:
                    alert:
                        type: list
                        elements: str
                        description: Alert multi-options.
                        choices: ['system-reboot', 'data-exhausted', 'session-disconnect',
                                  'low-signal-strength', 'mode-switch', 'os-image-fallback',
                                  'fgt-backup-mode-switch']
                    name:
                        type: str
                        description: FortiExtender SMS notification receiver name.
                    phone_number:
                        aliases: ['phone-number']
                        type: str
                        description: Receiver phone number.
                    status:
                        type: str
                        description: SMS notification receiver status.
                        choices: ['disable', 'enable']
            status:
                type: str
                description: FortiExtender SMS notification status.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiExtender cellular SMS notification configuration.
      fortinet.fortimanager.fmgr_extendercontroller_extenderprofile_cellular_smsnotification:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        extendercontroller_extenderprofile_cellular_smsnotification:
          # alert:
          #   data_exhausted: <string>
          #   fgt_backup_mode_switch: <string>
          #   low_signal_strength: <string>
          #   mode_switch: <string>
          #   os_image_fallback: <string>
          #   session_disconnect: <string>
          #   system_reboot: <string>
          # receiver:
          #   - alert: ["system-reboot", "data-exhausted", "session-disconnect",
          #             "low-signal-strength", "mode-switch", "os-image-fallback",
          #             "fgt-backup-mode-switch"]
          #     name: <string>
          #     phone_number: <string>
          #     status: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification',
        '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extendercontroller_extenderprofile_cellular_smsnotification': {
            'type': 'dict', 'v_range': [['7.0.2', '']],
            'options': {
                'alert': {
                    'v_range': [['7.0.2', '']],
                    'type': 'dict',
                    'options': {
                        'data-exhausted': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'fgt-backup-mode-switch': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'low-signal-strength': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'mode-switch': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'os-image-fallback': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'session-disconnect': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'system-reboot': {'v_range': [['7.0.2', '']], 'type': 'str'}
                    }
                },
                'receiver': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'alert': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'choices': [
                                'system-reboot', 'data-exhausted', 'session-disconnect', 'low-signal-strength', 'mode-switch', 'os-image-fallback',
                                'fgt-backup-mode-switch'
                            ],
                            'elements': 'str'
                        },
                        'name': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'phone-number': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'status': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extenderprofile_cellular_smsnotification'),
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
