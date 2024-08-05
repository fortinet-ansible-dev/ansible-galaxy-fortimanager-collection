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
module: fmgr_extensioncontroller_extenderprofile_wifi
short_description: FortiExtender wifi configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.6.0"
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
    extensioncontroller_extenderprofile_wifi:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            DFS:
                type: str
                description: Wi-Fi 5G Radio DFS channel enable/disable.
                choices:
                    - 'disable'
                    - 'enable'
            country:
                type: str
                description: Country in which this FEX will operate
                choices:
                    - 'AL'
                    - 'DZ'
                    - 'AR'
                    - 'AM'
                    - 'AU'
                    - 'AT'
                    - 'AZ'
                    - 'BH'
                    - 'BD'
                    - 'BY'
                    - 'BE'
                    - 'BZ'
                    - 'BO'
                    - 'BA'
                    - 'BR'
                    - 'BN'
                    - 'BG'
                    - 'CA'
                    - 'CL'
                    - 'CN'
                    - 'CO'
                    - 'CR'
                    - 'HR'
                    - 'CY'
                    - 'CZ'
                    - 'DK'
                    - 'DO'
                    - 'EC'
                    - 'EG'
                    - 'SV'
                    - 'EE'
                    - 'FI'
                    - 'FR'
                    - 'GE'
                    - 'DE'
                    - 'GR'
                    - 'GT'
                    - 'HN'
                    - 'HK'
                    - 'HU'
                    - 'IS'
                    - 'IN'
                    - 'ID'
                    - 'IE'
                    - 'IL'
                    - 'IT'
                    - 'JM'
                    - 'JP'
                    - 'JO'
                    - 'KZ'
                    - 'KE'
                    - 'KR'
                    - 'KW'
                    - 'LV'
                    - 'LB'
                    - 'LI'
                    - 'LT'
                    - 'LU'
                    - 'MO'
                    - 'MK'
                    - 'MY'
                    - 'MT'
                    - 'MX'
                    - 'MC'
                    - 'MA'
                    - 'NP'
                    - 'NL'
                    - 'AN'
                    - 'NZ'
                    - 'NO'
                    - 'OM'
                    - 'PK'
                    - 'PA'
                    - 'PG'
                    - 'PE'
                    - 'PH'
                    - 'PL'
                    - 'PT'
                    - 'PR'
                    - 'QA'
                    - 'RO'
                    - 'RU'
                    - 'SA'
                    - 'SG'
                    - 'SK'
                    - 'SI'
                    - 'ZA'
                    - 'ES'
                    - 'LK'
                    - 'SE'
                    - 'CH'
                    - 'TW'
                    - 'TH'
                    - 'TT'
                    - 'TN'
                    - 'TR'
                    - 'AE'
                    - 'UA'
                    - 'GB'
                    - 'US'
                    - 'PS'
                    - 'UY'
                    - 'UZ'
                    - 'VE'
                    - 'VN'
                    - 'YE'
                    - 'ZW'
                    - 'NA'
                    - 'BS'
                    - 'VC'
                    - 'KH'
                    - 'MV'
                    - 'AF'
                    - 'NG'
                    - 'TZ'
                    - 'ZM'
                    - 'SN'
                    - 'CI'
                    - 'GH'
                    - 'CM'
                    - 'MW'
                    - 'AO'
                    - 'GA'
                    - 'ML'
                    - 'BJ'
                    - 'MG'
                    - 'TD'
                    - 'BW'
                    - 'LY'
                    - 'RW'
                    - 'MZ'
                    - 'GM'
                    - 'LS'
                    - 'MU'
                    - 'CG'
                    - 'UG'
                    - 'BF'
                    - 'SL'
                    - 'SO'
                    - 'CD'
                    - 'NE'
                    - 'CF'
                    - 'SZ'
                    - 'TG'
                    - 'LR'
                    - 'MR'
                    - 'DJ'
                    - 'RE'
                    - 'RS'
                    - 'ME'
                    - 'IQ'
                    - 'MD'
                    - 'KY'
                    - 'BB'
                    - 'BM'
                    - 'TC'
                    - 'VI'
                    - 'PM'
                    - 'MF'
                    - 'GD'
                    - 'IM'
                    - 'FO'
                    - 'GI'
                    - 'GL'
                    - 'TM'
                    - 'MN'
                    - 'VU'
                    - 'FJ'
                    - 'LA'
                    - 'GU'
                    - 'WF'
                    - 'MH'
                    - 'BT'
                    - 'FM'
                    - 'PF'
                    - 'NI'
                    - 'PY'
                    - 'HT'
                    - 'GY'
                    - 'AW'
                    - 'KN'
                    - 'GF'
                    - 'AS'
                    - 'MP'
                    - 'PW'
                    - 'MM'
                    - 'LC'
                    - 'GP'
                    - 'ET'
                    - 'SR'
                    - 'CX'
                    - 'DM'
                    - 'MQ'
                    - 'YT'
                    - 'BL'
                    - '--'
            radio-1:
                type: dict
                description: Deprecated, please rename it to radio_1. Radio 1.
                suboptions:
                    80211d:
                        type: str
                        description: Deprecated, please rename it to d80211d. Enable/disable Wi-Fi 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    band:
                        type: str
                        description: Wi-Fi band selection 2.
                        choices:
                            - '2.4GHz'
                    bandwidth:
                        type: str
                        description: Wi-Fi channel bandwidth.
                        choices:
                            - 'auto'
                            - '20MHz'
                            - '40MHz'
                            - '80MHz'
                    beacon-interval:
                        type: int
                        description: Deprecated, please rename it to beacon_interval. Wi-Fi beacon interval in miliseconds
                    bss-color:
                        type: int
                        description: Deprecated, please rename it to bss_color. Wi-Fi 802.
                    bss-color-mode:
                        type: str
                        description: Deprecated, please rename it to bss_color_mode. Wi-Fi 802.
                        choices:
                            - 'auto'
                            - 'static'
                    channel:
                        type: list
                        elements: str
                        description: Wi-Fi channels.
                        choices:
                            - 'CH1'
                            - 'CH2'
                            - 'CH3'
                            - 'CH4'
                            - 'CH5'
                            - 'CH6'
                            - 'CH7'
                            - 'CH8'
                            - 'CH9'
                            - 'CH10'
                            - 'CH11'
                    extension-channel:
                        type: str
                        description: Deprecated, please rename it to extension_channel. Wi-Fi extension channel.
                        choices:
                            - 'auto'
                            - 'higher'
                            - 'lower'
                    guard-interval:
                        type: str
                        description: Deprecated, please rename it to guard_interval. Wi-Fi guard interval.
                        choices:
                            - 'auto'
                            - '400ns'
                            - '800ns'
                    lan-ext-vap:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to lan_ext_vap. Wi-Fi LAN-Extention VAP.
                    local-vaps:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to local_vaps. Wi-Fi local VAP.
                    max-clients:
                        type: int
                        description: Deprecated, please rename it to max_clients. Maximum number of Wi-Fi radio clients
                    mode:
                        type: str
                        description: Wi-Fi radio mode AP
                        choices:
                            - 'AP'
                            - 'Client'
                    operating-standard:
                        type: str
                        description: Deprecated, please rename it to operating_standard. Wi-Fi operating standard.
                        choices:
                            - 'auto'
                            - '11A-N-AC-AX'
                            - '11A-N-AC'
                            - '11A-N'
                            - '11A'
                            - '11N-AC-AX'
                            - '11AC-AX'
                            - '11AC'
                            - '11N-AC'
                            - '11B-G-N-AX'
                            - '11B-G-N'
                            - '11B-G'
                            - '11B'
                            - '11G-N-AX'
                            - '11N-AX'
                            - '11AX'
                            - '11G-N'
                            - '11N'
                            - '11G'
                    power-level:
                        type: int
                        description: Deprecated, please rename it to power_level. Wi-Fi power level in percent
                    radio-id:
                        type: int
                        description: Deprecated, please rename it to radio_id. Radio ID.
                    status:
                        type: str
                        description: Enable/disable Wi-Fi radio.
                        choices:
                            - 'disable'
                            - 'enable'
            radio-2:
                type: dict
                description: Deprecated, please rename it to radio_2. Radio 2.
                suboptions:
                    80211d:
                        type: str
                        description: Deprecated, please rename it to d80211d. Enable/disable Wi-Fi 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    band:
                        type: str
                        description: Wi-Fi band selection 2.
                        choices:
                            - '5GHz'
                    bandwidth:
                        type: str
                        description: Wi-Fi channel bandwidth.
                        choices:
                            - 'auto'
                            - '20MHz'
                            - '40MHz'
                            - '80MHz'
                    beacon-interval:
                        type: int
                        description: Deprecated, please rename it to beacon_interval. Wi-Fi beacon interval in miliseconds
                    bss-color:
                        type: int
                        description: Deprecated, please rename it to bss_color. Wi-Fi 802.
                    bss-color-mode:
                        type: str
                        description: Deprecated, please rename it to bss_color_mode. Wi-Fi 802.
                        choices:
                            - 'auto'
                            - 'static'
                    channel:
                        type: list
                        elements: str
                        description: Wi-Fi channels.
                        choices:
                            - 'CH36'
                            - 'CH40'
                            - 'CH44'
                            - 'CH48'
                            - 'CH52'
                            - 'CH56'
                            - 'CH60'
                            - 'CH64'
                            - 'CH100'
                            - 'CH104'
                            - 'CH108'
                            - 'CH112'
                            - 'CH116'
                            - 'CH120'
                            - 'CH124'
                            - 'CH128'
                            - 'CH132'
                            - 'CH136'
                            - 'CH140'
                            - 'CH144'
                            - 'CH149'
                            - 'CH153'
                            - 'CH157'
                            - 'CH161'
                            - 'CH165'
                    extension-channel:
                        type: str
                        description: Deprecated, please rename it to extension_channel. Wi-Fi extension channel.
                        choices:
                            - 'auto'
                            - 'higher'
                            - 'lower'
                    guard-interval:
                        type: str
                        description: Deprecated, please rename it to guard_interval. Wi-Fi guard interval.
                        choices:
                            - 'auto'
                            - '400ns'
                            - '800ns'
                    lan-ext-vap:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to lan_ext_vap. Wi-Fi LAN-Extention VAP.
                    local-vaps:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to local_vaps. Wi-Fi local VAP.
                    max-clients:
                        type: int
                        description: Deprecated, please rename it to max_clients. Maximum number of Wi-Fi radio clients
                    mode:
                        type: str
                        description: Wi-Fi radio mode AP
                        choices:
                            - 'AP'
                            - 'Client'
                    operating-standard:
                        type: str
                        description: Deprecated, please rename it to operating_standard. Wi-Fi operating standard.
                        choices:
                            - 'auto'
                            - '11A-N-AC-AX'
                            - '11A-N-AC'
                            - '11A-N'
                            - '11A'
                            - '11N-AC-AX'
                            - '11AC-AX'
                            - '11AC'
                            - '11N-AC'
                            - '11B-G-N-AX'
                            - '11B-G-N'
                            - '11B-G'
                            - '11B'
                            - '11G-N-AX'
                            - '11N-AX'
                            - '11AX'
                            - '11G-N'
                            - '11N'
                            - '11G'
                    power-level:
                        type: int
                        description: Deprecated, please rename it to power_level. Wi-Fi power level in percent
                    radio-id:
                        type: int
                        description: Deprecated, please rename it to radio_id. Radio ID.
                    status:
                        type: str
                        description: Enable/disable Wi-Fi radio.
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
    - name: FortiExtender wifi configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_wifi:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        extender_profile: <your own value>
        extensioncontroller_extenderprofile_wifi:
          DFS: <value in [disable, enable]>
          country: <value in [AL, DZ, AR, ...]>
          radio_1:
            d80211d: <value in [disable, enable]>
            band: <value in [2.4GHz]>
            bandwidth: <value in [auto, 20MHz, 40MHz, ...]>
            beacon_interval: <integer>
            bss_color: <integer>
            bss_color_mode: <value in [auto, static]>
            channel:
              - CH1
              - CH2
              - CH3
              - CH4
              - CH5
              - CH6
              - CH7
              - CH8
              - CH9
              - CH10
              - CH11
            extension_channel: <value in [auto, higher, lower]>
            guard_interval: <value in [auto, 400ns, 800ns]>
            lan_ext_vap: <list or string>
            local_vaps: <list or string>
            max_clients: <integer>
            mode: <value in [AP, Client]>
            operating_standard: <value in [auto, 11A-N-AC-AX, 11A-N-AC, ...]>
            power_level: <integer>
            radio_id: <integer>
            status: <value in [disable, enable]>
          radio_2:
            d80211d: <value in [disable, enable]>
            band: <value in [5GHz]>
            bandwidth: <value in [auto, 20MHz, 40MHz, ...]>
            beacon_interval: <integer>
            bss_color: <integer>
            bss_color_mode: <value in [auto, static]>
            channel:
              - CH36
              - CH40
              - CH44
              - CH48
              - CH52
              - CH56
              - CH60
              - CH64
              - CH100
              - CH104
              - CH108
              - CH112
              - CH116
              - CH120
              - CH124
              - CH128
              - CH132
              - CH136
              - CH140
              - CH144
              - CH149
              - CH153
              - CH157
              - CH161
              - CH165
            extension_channel: <value in [auto, higher, lower]>
            guard_interval: <value in [auto, 400ns, 800ns]>
            lan_ext_vap: <list or string>
            local_vaps: <list or string>
            max_clients: <integer>
            mode: <value in [AP, Client]>
            operating_standard: <value in [auto, 11A-N-AC-AX, 11A-N-AC, ...]>
            power_level: <integer>
            radio_id: <integer>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi/{wifi}',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi/{wifi}'
    ]

    url_params = ['adom', 'extender-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'extensioncontroller_extenderprofile_wifi': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'DFS': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'country': {
                    'v_range': [['7.4.3', '']],
                    'choices': [
                        'AL', 'DZ', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BZ', 'BO', 'BA', 'BR', 'BN', 'BG', 'CA', 'CL', 'CN', 'CO',
                        'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GE', 'DE', 'GR', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN',
                        'ID', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KR', 'KW', 'LV', 'LB', 'LI', 'LT', 'LU', 'MO', 'MK', 'MY', 'MT', 'MX',
                        'MC', 'MA', 'NP', 'NL', 'AN', 'NZ', 'NO', 'OM', 'PK', 'PA', 'PG', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RO', 'RU', 'SA', 'SG',
                        'SK', 'SI', 'ZA', 'ES', 'LK', 'SE', 'CH', 'TW', 'TH', 'TT', 'TN', 'TR', 'AE', 'UA', 'GB', 'US', 'PS', 'UY', 'UZ', 'VE', 'VN',
                        'YE', 'ZW', 'NA', 'BS', 'VC', 'KH', 'MV', 'AF', 'NG', 'TZ', 'ZM', 'SN', 'CI', 'GH', 'CM', 'MW', 'AO', 'GA', 'ML', 'BJ', 'MG',
                        'TD', 'BW', 'LY', 'RW', 'MZ', 'GM', 'LS', 'MU', 'CG', 'UG', 'BF', 'SL', 'SO', 'CD', 'NE', 'CF', 'SZ', 'TG', 'LR', 'MR', 'DJ',
                        'RE', 'RS', 'ME', 'IQ', 'MD', 'KY', 'BB', 'BM', 'TC', 'VI', 'PM', 'MF', 'GD', 'IM', 'FO', 'GI', 'GL', 'TM', 'MN', 'VU', 'FJ',
                        'LA', 'GU', 'WF', 'MH', 'BT', 'FM', 'PF', 'NI', 'PY', 'HT', 'GY', 'AW', 'KN', 'GF', 'AS', 'MP', 'PW', 'MM', 'LC', 'GP', 'ET',
                        'SR', 'CX', 'DM', 'MQ', 'YT', 'BL', '--'
                    ],
                    'type': 'str'
                },
                'radio-1': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        '80211d': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'band': {'v_range': [['7.4.3', '']], 'choices': ['2.4GHz'], 'type': 'str'},
                        'bandwidth': {'v_range': [['7.4.3', '']], 'choices': ['auto', '20MHz', '40MHz', '80MHz'], 'type': 'str'},
                        'beacon-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'bss-color-mode': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'channel': {
                            'v_range': [['7.4.3', '']],
                            'type': 'list',
                            'choices': ['CH1', 'CH2', 'CH3', 'CH4', 'CH5', 'CH6', 'CH7', 'CH8', 'CH9', 'CH10', 'CH11'],
                            'elements': 'str'
                        },
                        'extension-channel': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'higher', 'lower'], 'type': 'str'},
                        'guard-interval': {'v_range': [['7.4.3', '']], 'choices': ['auto', '400ns', '800ns'], 'type': 'str'},
                        'lan-ext-vap': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'local-vaps': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'max-clients': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'mode': {'v_range': [['7.4.3', '']], 'choices': ['AP', 'Client'], 'type': 'str'},
                        'operating-standard': {
                            'v_range': [['7.4.3', '']],
                            'choices': [
                                'auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX', '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX', '11B-G-N',
                                '11B-G', '11B', '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G'
                            ],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'radio-2': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        '80211d': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'band': {'v_range': [['7.4.3', '']], 'choices': ['5GHz'], 'type': 'str'},
                        'bandwidth': {'v_range': [['7.4.3', '']], 'choices': ['auto', '20MHz', '40MHz', '80MHz'], 'type': 'str'},
                        'beacon-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'bss-color-mode': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'channel': {
                            'v_range': [['7.4.3', '']],
                            'type': 'list',
                            'choices': [
                                'CH36', 'CH40', 'CH44', 'CH48', 'CH52', 'CH56', 'CH60', 'CH64', 'CH100', 'CH104', 'CH108', 'CH112', 'CH116', 'CH120',
                                'CH124', 'CH128', 'CH132', 'CH136', 'CH140', 'CH144', 'CH149', 'CH153', 'CH157', 'CH161', 'CH165'
                            ],
                            'elements': 'str'
                        },
                        'extension-channel': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'higher', 'lower'], 'type': 'str'},
                        'guard-interval': {'v_range': [['7.4.3', '']], 'choices': ['auto', '400ns', '800ns'], 'type': 'str'},
                        'lan-ext-vap': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'local-vaps': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'max-clients': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'mode': {'v_range': [['7.4.3', '']], 'choices': ['AP', 'Client'], 'type': 'str'},
                        'operating-standard': {
                            'v_range': [['7.4.3', '']],
                            'choices': [
                                'auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX', '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX', '11B-G-N',
                                '11B-G', '11B', '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G'
                            ],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'radio-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_wifi'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
