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
module: fmgr_extensioncontroller_extenderprofile_cellular
short_description: FortiExtender cellular configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    extensioncontroller_extenderprofile_cellular:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            controller-report:
                type: dict
                description: Deprecated, please rename it to controller_report.
                suboptions:
                    interval:
                        type: int
                        description: Controller report interval.
                    signal-threshold:
                        type: int
                        description: Deprecated, please rename it to signal_threshold. Controller report signal threshold.
                    status:
                        type: str
                        description: FortiExtender controller report status.
                        choices:
                            - 'disable'
                            - 'enable'
            dataplan:
                type: raw
                description: (list) No description.
            modem1:
                type: dict
                description: No description.
                suboptions:
                    auto-switch:
                        type: dict
                        description: Deprecated, please rename it to auto_switch.
                        suboptions:
                            dataplan:
                                type: str
                                description: Automatically switch based on data usage.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            disconnect:
                                type: str
                                description: Auto switch by disconnect.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            disconnect-period:
                                type: int
                                description: Deprecated, please rename it to disconnect_period. Automatically switch based on disconnect period.
                            disconnect-threshold:
                                type: int
                                description: Deprecated, please rename it to disconnect_threshold. Automatically switch based on disconnect threshold.
                            signal:
                                type: str
                                description: Automatically switch based on signal strength.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            switch-back:
                                type: list
                                elements: str
                                description: Deprecated, please rename it to switch_back.
                                choices:
                                    - 'time'
                                    - 'timer'
                            switch-back-time:
                                type: str
                                description: Deprecated, please rename it to switch_back_time. Automatically switch over to preferred SIM/carrier at a ...
                            switch-back-timer:
                                type: int
                                description: Deprecated, please rename it to switch_back_timer. Automatically switch over to preferred SIM/carrier afte...
                    conn-status:
                        type: int
                        description: Deprecated, please rename it to conn_status.
                    default-sim:
                        type: str
                        description: Deprecated, please rename it to default_sim. Default SIM selection.
                        choices:
                            - 'sim1'
                            - 'sim2'
                            - 'carrier'
                            - 'cost'
                    gps:
                        type: str
                        description: FortiExtender GPS enable/disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    modem-id:
                        type: int
                        description: Deprecated, please rename it to modem_id. Modem ID.
                    preferred-carrier:
                        type: str
                        description: Deprecated, please rename it to preferred_carrier. Preferred carrier.
                    redundant-intf:
                        type: str
                        description: Deprecated, please rename it to redundant_intf. Redundant interface.
                    redundant-mode:
                        type: str
                        description: Deprecated, please rename it to redundant_mode. FortiExtender mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim1-pin:
                        type: str
                        description: Deprecated, please rename it to sim1_pin. SIM #1 PIN status.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim1-pin-code:
                        type: raw
                        description: (list) Deprecated, please rename it to sim1_pin_code.
                    sim2-pin:
                        type: str
                        description: Deprecated, please rename it to sim2_pin. SIM #2 PIN status.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim2-pin-code:
                        type: raw
                        description: (list) Deprecated, please rename it to sim2_pin_code.
            modem2:
                type: dict
                description: No description.
                suboptions:
                    auto-switch:
                        type: dict
                        description: Deprecated, please rename it to auto_switch.
                        suboptions:
                            dataplan:
                                type: str
                                description: Automatically switch based on data usage.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            disconnect:
                                type: str
                                description: Auto switch by disconnect.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            disconnect-period:
                                type: int
                                description: Deprecated, please rename it to disconnect_period. Automatically switch based on disconnect period.
                            disconnect-threshold:
                                type: int
                                description: Deprecated, please rename it to disconnect_threshold. Automatically switch based on disconnect threshold.
                            signal:
                                type: str
                                description: Automatically switch based on signal strength.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            switch-back:
                                type: list
                                elements: str
                                description: Deprecated, please rename it to switch_back.
                                choices:
                                    - 'time'
                                    - 'timer'
                            switch-back-time:
                                type: str
                                description: Deprecated, please rename it to switch_back_time. Automatically switch over to preferred SIM/carrier at a ...
                            switch-back-timer:
                                type: int
                                description: Deprecated, please rename it to switch_back_timer. Automatically switch over to preferred SIM/carrier afte...
                    conn-status:
                        type: int
                        description: Deprecated, please rename it to conn_status.
                    default-sim:
                        type: str
                        description: Deprecated, please rename it to default_sim. Default SIM selection.
                        choices:
                            - 'sim1'
                            - 'sim2'
                            - 'carrier'
                            - 'cost'
                    gps:
                        type: str
                        description: FortiExtender GPS enable/disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    modem-id:
                        type: int
                        description: Deprecated, please rename it to modem_id. Modem ID.
                    preferred-carrier:
                        type: str
                        description: Deprecated, please rename it to preferred_carrier. Preferred carrier.
                    redundant-intf:
                        type: str
                        description: Deprecated, please rename it to redundant_intf. Redundant interface.
                    redundant-mode:
                        type: str
                        description: Deprecated, please rename it to redundant_mode. FortiExtender mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim1-pin:
                        type: str
                        description: Deprecated, please rename it to sim1_pin. SIM #1 PIN status.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim1-pin-code:
                        type: raw
                        description: (list) Deprecated, please rename it to sim1_pin_code.
                    sim2-pin:
                        type: str
                        description: Deprecated, please rename it to sim2_pin. SIM #2 PIN status.
                        choices:
                            - 'disable'
                            - 'enable'
                    sim2-pin-code:
                        type: raw
                        description: (list) Deprecated, please rename it to sim2_pin_code.
            sms-notification:
                type: dict
                description: Deprecated, please rename it to sms_notification.
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
    - name: FortiExtender cellular configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        extender_profile: <your own value>
        extensioncontroller_extenderprofile_cellular:
          controller_report:
            interval: <integer>
            signal_threshold: <integer>
            status: <value in [disable, enable]>
          dataplan: <list or string>
          modem1:
            auto_switch:
              dataplan: <value in [disable, enable]>
              disconnect: <value in [disable, enable]>
              disconnect_period: <integer>
              disconnect_threshold: <integer>
              signal: <value in [disable, enable]>
              switch_back:
                - time
                - timer
              switch_back_time: <string>
              switch_back_timer: <integer>
            conn_status: <integer>
            default_sim: <value in [sim1, sim2, carrier, ...]>
            gps: <value in [disable, enable]>
            modem_id: <integer>
            preferred_carrier: <string>
            redundant_intf: <string>
            redundant_mode: <value in [disable, enable]>
            sim1_pin: <value in [disable, enable]>
            sim1_pin_code: <list or string>
            sim2_pin: <value in [disable, enable]>
            sim2_pin_code: <list or string>
          modem2:
            auto_switch:
              dataplan: <value in [disable, enable]>
              disconnect: <value in [disable, enable]>
              disconnect_period: <integer>
              disconnect_threshold: <integer>
              signal: <value in [disable, enable]>
              switch_back:
                - time
                - timer
              switch_back_time: <string>
              switch_back_timer: <integer>
            conn_status: <integer>
            default_sim: <value in [sim1, sim2, carrier, ...]>
            gps: <value in [disable, enable]>
            modem_id: <integer>
            preferred_carrier: <string>
            redundant_intf: <string>
            redundant_mode: <value in [disable, enable]>
            sim1_pin: <value in [disable, enable]>
            sim1_pin_code: <list or string>
            sim2_pin: <value in [disable, enable]>
            sim2_pin_code: <list or string>
          sms_notification:
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/{cellular}',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/{cellular}'
    ]

    url_params = ['adom', 'extender-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'extensioncontroller_extenderprofile_cellular': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'controller-report': {
                    'type': 'dict',
                    'options': {
                        'interval': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'signal-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'dataplan': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'modem1': {
                    'type': 'dict',
                    'options': {
                        'auto-switch': {
                            'type': 'dict',
                            'options': {
                                'dataplan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'disconnect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'disconnect-period': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'disconnect-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'signal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'switch-back': {'v_range': [['7.2.1', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                                'switch-back-time': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'switch-back-timer': {'v_range': [['7.2.1', '']], 'type': 'int'}
                            }
                        },
                        'conn-status': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'default-sim': {'v_range': [['7.2.1', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                        'gps': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'modem-id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'preferred-carrier': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'redundant-intf': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'redundant-mode': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim1-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim1-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'sim2-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim2-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'}
                    }
                },
                'modem2': {
                    'type': 'dict',
                    'options': {
                        'auto-switch': {
                            'type': 'dict',
                            'options': {
                                'dataplan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'disconnect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'disconnect-period': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'disconnect-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'signal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'switch-back': {'v_range': [['7.2.1', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                                'switch-back-time': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'switch-back-timer': {'v_range': [['7.2.1', '']], 'type': 'int'}
                            }
                        },
                        'conn-status': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'default-sim': {'v_range': [['7.2.1', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                        'gps': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'modem-id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'preferred-carrier': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'redundant-intf': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'redundant-mode': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim1-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim1-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'sim2-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sim2-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'}
                    }
                },
                'sms-notification': {
                    'type': 'dict',
                    'options': {
                        'alert': {
                            'type': 'dict',
                            'options': {
                                'data-exhausted': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'fgt-backup-mode-switch': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'low-signal-strength': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'mode-switch': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'os-image-fallback': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'session-disconnect': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'system-reboot': {'v_range': [['7.2.1', '']], 'type': 'str'}
                            }
                        },
                        'receiver': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'alert': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'list',
                                    'choices': [
                                        'system-reboot', 'data-exhausted', 'session-disconnect', 'low-signal-strength', 'mode-switch',
                                        'os-image-fallback', 'fgt-backup-mode-switch'
                                    ],
                                    'elements': 'str'
                                },
                                'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'phone-number': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_cellular'),
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
