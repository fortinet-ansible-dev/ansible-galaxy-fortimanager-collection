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
module: fmgr_arrpprofile
short_description: Configure WiFi Automatic Radio Resource Provisioning
version_added: "2.1.0"
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
    arrpprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            darrp_optimize:
                aliases: ['darrp-optimize']
                type: int
                description: Time for running Dynamic Automatic Radio Resource Provisioning
            darrp_optimize_schedules:
                aliases: ['darrp-optimize-schedules']
                type: raw
                description: (list) Firewall schedules for DARRP running time.
            include_dfs_channel:
                aliases: ['include-dfs-channel']
                type: str
                description: Enable/disable use of DFS channel in DARRP channel selection phase 1
                choices: ['no', 'disable', 'yes', 'enable']
            include_weather_channel:
                aliases: ['include-weather-channel']
                type: str
                description: Enable/disable use of weather channel in DARRP channel selection phase 1
                choices: ['no', 'disable', 'yes', 'enable']
            monitor_period:
                aliases: ['monitor-period']
                type: int
                description: Period in seconds to measure average transmit retries and receive errors
            name:
                type: str
                description: WiFi ARRP profile name.
                required: true
            override_darrp_optimize:
                aliases: ['override-darrp-optimize']
                type: str
                description: Enable to override setting darrp-optimize and darrp-optimize-schedules
                choices: ['disable', 'enable']
            selection_period:
                aliases: ['selection-period']
                type: int
                description: Period in seconds to measure average channel load, noise floor, spectral RSSI
            threshold_ap:
                aliases: ['threshold-ap']
                type: int
                description: Threshold to reject channel in DARRP channel selection phase 1 due to surrounding APs
            threshold_channel_load:
                aliases: ['threshold-channel-load']
                type: int
                description: Threshold in percentage to reject channel in DARRP channel selection phase 1 due to channel load
            threshold_noise_floor:
                aliases: ['threshold-noise-floor']
                type: str
                description: Threshold in dBm to reject channel in DARRP channel selection phase 1 due to noise floor
            threshold_rx_errors:
                aliases: ['threshold-rx-errors']
                type: int
                description: Threshold in percentage for receive errors to trigger channel reselection in DARRP monitor stage
            threshold_spectral_rssi:
                aliases: ['threshold-spectral-rssi']
                type: str
                description: Threshold in dBm to reject channel in DARRP channel selection phase 1 due to spectral RSSI
            threshold_tx_retries:
                aliases: ['threshold-tx-retries']
                type: int
                description: Threshold in percentage for transmit retries to trigger channel reselection in DARRP monitor stage
            weight_channel_load:
                aliases: ['weight-channel-load']
                type: int
                description: Weight in DARRP channel score calculation for channel load
            weight_dfs_channel:
                aliases: ['weight-dfs-channel']
                type: int
                description: Weight in DARRP channel score calculation for DFS channel
            weight_managed_ap:
                aliases: ['weight-managed-ap']
                type: int
                description: Weight in DARRP channel score calculation for managed APs
            weight_noise_floor:
                aliases: ['weight-noise-floor']
                type: int
                description: Weight in DARRP channel score calculation for noise floor
            weight_rogue_ap:
                aliases: ['weight-rogue-ap']
                type: int
                description: Weight in DARRP channel score calculation for rogue APs
            weight_spectral_rssi:
                aliases: ['weight-spectral-rssi']
                type: int
                description: Weight in DARRP channel score calculation for spectral RSSI
            weight_weather_channel:
                aliases: ['weight-weather-channel']
                type: int
                description: Weight in DARRP channel score calculation for weather channel
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WiFi Automatic Radio Resource Provisioning
      fortinet.fortimanager.fmgr_arrpprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        arrpprofile:
          name: "your value" # Required variable, string
          # comment: <string>
          # darrp_optimize: <integer>
          # darrp_optimize_schedules: <list or string>
          # include_dfs_channel: <value in [no, disable, yes, ...]>
          # include_weather_channel: <value in [no, disable, yes, ...]>
          # monitor_period: <integer>
          # override_darrp_optimize: <value in [disable, enable]>
          # selection_period: <integer>
          # threshold_ap: <integer>
          # threshold_channel_load: <integer>
          # threshold_noise_floor: <string>
          # threshold_rx_errors: <integer>
          # threshold_spectral_rssi: <string>
          # threshold_tx_retries: <integer>
          # weight_channel_load: <integer>
          # weight_dfs_channel: <integer>
          # weight_managed_ap: <integer>
          # weight_noise_floor: <integer>
          # weight_rogue_ap: <integer>
          # weight_spectral_rssi: <integer>
          # weight_weather_channel: <integer>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile',
        '/pm/config/global/obj/wireless-controller/arrp-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'arrpprofile': {
            'type': 'dict', 'v_range': [['7.0.3', '']],
            'options': {
                'comment': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'darrp-optimize': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'darrp-optimize-schedules': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'include-dfs-channel': {'v_range': [['7.0.3', '']], 'choices': ['no', 'disable', 'yes', 'enable'], 'type': 'str'},
                'include-weather-channel': {'v_range': [['7.0.3', '']], 'choices': ['no', 'disable', 'yes', 'enable'], 'type': 'str'},
                'monitor-period': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.0.3', '']], 'required': True, 'type': 'str'},
                'override-darrp-optimize': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'selection-period': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'threshold-ap': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'threshold-channel-load': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'threshold-noise-floor': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'threshold-rx-errors': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'threshold-spectral-rssi': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'threshold-tx-retries': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-channel-load': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-dfs-channel': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-managed-ap': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-noise-floor': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-rogue-ap': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-spectral-rssi': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'weight-weather-channel': {'v_range': [['7.0.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'arrpprofile'),
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
