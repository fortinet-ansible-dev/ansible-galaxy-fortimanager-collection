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
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
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
                description: No description.
                suboptions:
                    data-exhausted:
                        type: str
                        description: Deprecated, please rename it to data_exhausted. Display string when data exhausted.
                    fgt-backup-mode-switch:
                        type: str
                        description: Deprecated, please rename it to fgt_backup_mode_switch. Display string when FortiGate backup mode switched.
                    low-signal-strength:
                        type: str
                        description: Deprecated, please rename it to low_signal_strength. Display string when signal strength is low.
                    mode-switch:
                        type: str
                        description: Deprecated, please rename it to mode_switch. Display string when mode is switched.
                    os-image-fallback:
                        type: str
                        description: Deprecated, please rename it to os_image_fallback. Display string when falling back to a previous OS image.
                    session-disconnect:
                        type: str
                        description: Deprecated, please rename it to session_disconnect. Display string when session disconnected.
                    system-reboot:
                        type: str
                        description: Deprecated, please rename it to system_reboot. Display string when system rebooted.
            receiver:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    alert:
                        type: list
                        elements: str
                        description: No description.
                        choices:
                            - 'system-reboot'
                            - 'data-exhausted'
                            - 'session-disconnect'
                            - 'low-signal-strength'
                            - 'mode-switch'
                            - 'os-image-fallback'
                            - 'fgt-backup-mode-switch'
                    name:
                        type: str
                        description: FortiExtender SMS notification receiver name.
                    phone-number:
                        type: str
                        description: Deprecated, please rename it to phone_number. Receiver phone number.
                    status:
                        type: str
                        description: SMS notification receiver status.
                        choices:
                            - 'disable'
                            - 'enable'
            status:
                type: str
                description: FortiExtender SMS notification status.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: FortiExtender cellular SMS notification configuration.
      fortinet.fortimanager.fmgr_extendercontroller_extenderprofile_cellular_smsnotification:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        extender_profile: <your own value>
        extendercontroller_extenderprofile_cellular_smsnotification:
          alert:
            data_exhausted: <string>
            fgt_backup_mode_switch: <string>
            low_signal_strength: <string>
            mode_switch: <string>
            os_image_fallback: <string>
            session_disconnect: <string>
            system_reboot: <string>
          receiver:
            -
              alert:
                - system-reboot
                - data-exhausted
                - session-disconnect
                - low-signal-strength
                - mode-switch
                - os-image-fallback
                - fgt-backup-mode-switch
              name: <string>
              phone_number: <string>
              status: <value in [disable, enable]>
          status: <value in [disable, enable]>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification',
        '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/{sms-notification}',
        '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/{sms-notification}'
    ]

    url_params = ['adom', 'extender-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'extendercontroller_extenderprofile_cellular_smsnotification': {
            'type': 'dict',
            'v_range': [['7.0.2', '']],
            'options': {
                'alert': {
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
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extenderprofile_cellular_smsnotification'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
