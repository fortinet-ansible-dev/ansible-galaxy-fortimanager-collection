#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_wtpprofile
short_description: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    wtpprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            allowaccess:
                description: no description
                type: list
                choices:
                 - https
                 - ssh
                 - snmp
                 - http
                 - telnet
            ap-country:
                type: str
                description: 'Country in which this WTP, FortiAP or AP will operate (default = NA, automatically use the country configured for the current ...'
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
                    - 'IR'
                    - 'IE'
                    - 'IL'
                    - 'IT'
                    - 'JM'
                    - 'JP'
                    - 'JO'
                    - 'KZ'
                    - 'KE'
                    - 'KP'
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
                    - 'SY'
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
                    - 'KH'
                    - 'TZ'
                    - 'SD'
                    - 'AO'
                    - 'RW'
                    - 'MZ'
                    - 'RS'
                    - 'ME'
                    - 'BB'
                    - 'GD'
                    - 'GL'
                    - 'GU'
                    - 'PY'
                    - 'HT'
                    - 'AW'
                    - 'MM'
                    - 'ZB'
            ble-profile:
                type: str
                description: 'Bluetooth Low Energy profile name.'
            comment:
                type: str
                description: 'Comment.'
            control-message-offload:
                description: no description
                type: list
                choices:
                 - ebp-frame
                 - aeroscout-tag
                 - ap-list
                 - sta-list
                 - sta-cap-list
                 - stats
                 - aeroscout-mu
                 - sta-health
            deny-mac-list:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: 'ID.'
                    mac:
                        type: str
                        description: 'A WiFi device with this MAC address is denied access to this WTP, FortiAP or AP.'
            dtls-in-kernel:
                type: str
                description: 'Enable/disable data channel DTLS in kernel.'
                choices:
                    - 'disable'
                    - 'enable'
            dtls-policy:
                description: no description
                type: list
                choices:
                 - clear-text
                 - dtls-enabled
                 - ipsec-vpn
            energy-efficient-ethernet:
                type: str
                description: 'Enable/disable use of energy efficient Ethernet on WTP.'
                choices:
                    - 'disable'
                    - 'enable'
            ext-info-enable:
                type: str
                description: 'Enable/disable station/VAP/radio extension information.'
                choices:
                    - 'disable'
                    - 'enable'
            handoff-roaming:
                type: str
                description: 'Enable/disable client load balancing during roaming to avoid roaming delay (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            handoff-rssi:
                type: int
                description: 'Minimum received signal strength indicator (RSSI) value for handoff (20 - 30, default = 25).'
            handoff-sta-thresh:
                type: int
                description: 'Threshold value for AP handoff.'
            ip-fragment-preventing:
                description: no description
                type: list
                choices:
                 - tcp-mss-adjust
                 - icmp-unreachable
            led-schedules:
                type: str
                description: 'Recurring firewall schedules for illuminating LEDs on the FortiAP. If led-state is enabled, LEDs will be visible when at least...'
            led-state:
                type: str
                description: 'Enable/disable use of LEDs on WTP (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            lldp:
                type: str
                description: 'Enable/disable Link Layer Discovery Protocol (LLDP) for the WTP, FortiAP, or AP (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            login-passwd:
                description: no description
                type: str
            login-passwd-change:
                type: str
                description: 'Change or reset the administrator password of a managed WTP, FortiAP or AP (yes, default, or no, default = no).'
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            max-clients:
                type: int
                description: 'Maximum number of stations (STAs) supported by the WTP (default = 0, meaning no client limitation).'
            name:
                type: str
                description: 'WTP (or FortiAP or AP) profile name.'
            poe-mode:
                type: str
                description: 'Set the WTP, FortiAP, or APs PoE mode.'
                choices:
                    - 'auto'
                    - '8023af'
                    - '8023at'
                    - 'power-adapter'
            split-tunneling-acl:
                description: no description
                type: list
                suboptions:
                    dest-ip:
                        type: str
                        description: 'Destination IP and mask for the split-tunneling subnet.'
                    id:
                        type: int
                        description: 'ID.'
            split-tunneling-acl-local-ap-subnet:
                type: str
                description: 'Enable/disable automatically adding local subnetwork of FortiAP to split-tunneling ACL (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-acl-path:
                type: str
                description: 'Split tunneling ACL path is local/tunnel.'
                choices:
                    - 'tunnel'
                    - 'local'
            tun-mtu-downlink:
                type: int
                description: 'Downlink CAPWAP tunnel MTU (0, 576, or 1500 bytes, default = 0).'
            tun-mtu-uplink:
                type: int
                description: 'Uplink CAPWAP tunnel MTU (0, 576, or 1500 bytes, default = 0).'
            wan-port-mode:
                type: str
                description: 'Enable/disable using a WAN port as a LAN port.'
                choices:
                    - 'wan-lan'
                    - 'wan-only'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
      fmgr_wtpprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         wtpprofile:
            allowaccess:
              - https
              - ssh
              - snmp
              - http
              - telnet
            ap-country: <value in [AL, DZ, AR, ...]>
            ble-profile: <value of string>
            comment: <value of string>
            control-message-offload:
              - ebp-frame
              - aeroscout-tag
              - ap-list
              - sta-list
              - sta-cap-list
              - stats
              - aeroscout-mu
              - sta-health
            deny-mac-list:
              -
                  id: <value of integer>
                  mac: <value of string>
            dtls-in-kernel: <value in [disable, enable]>
            dtls-policy:
              - clear-text
              - dtls-enabled
              - ipsec-vpn
            energy-efficient-ethernet: <value in [disable, enable]>
            ext-info-enable: <value in [disable, enable]>
            handoff-roaming: <value in [disable, enable]>
            handoff-rssi: <value of integer>
            handoff-sta-thresh: <value of integer>
            ip-fragment-preventing:
              - tcp-mss-adjust
              - icmp-unreachable
            led-schedules: <value of string>
            led-state: <value in [disable, enable]>
            lldp: <value in [disable, enable]>
            login-passwd: <value of string>
            login-passwd-change: <value in [no, yes, default]>
            max-clients: <value of integer>
            name: <value of string>
            poe-mode: <value in [auto, 8023af, 8023at, ...]>
            split-tunneling-acl:
              -
                  dest-ip: <value of string>
                  id: <value of integer>
            split-tunneling-acl-local-ap-subnet: <value in [disable, enable]>
            split-tunneling-acl-path: <value in [tunnel, local]>
            tun-mtu-downlink: <value of integer>
            tun-mtu-uplink: <value of integer>
            wan-port-mode: <value in [wan-lan, wan-only]>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile',
        '/pm/config/global/obj/wireless-controller/wtp-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'wtpprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                'allowaccess': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'https',
                        'ssh',
                        'snmp',
                        'http',
                        'telnet'
                    ]
                },
                'ap-country': {
                    'required': False,
                    'choices': [
                        'AL',
                        'DZ',
                        'AR',
                        'AM',
                        'AU',
                        'AT',
                        'AZ',
                        'BH',
                        'BD',
                        'BY',
                        'BE',
                        'BZ',
                        'BO',
                        'BA',
                        'BR',
                        'BN',
                        'BG',
                        'CA',
                        'CL',
                        'CN',
                        'CO',
                        'CR',
                        'HR',
                        'CY',
                        'CZ',
                        'DK',
                        'DO',
                        'EC',
                        'EG',
                        'SV',
                        'EE',
                        'FI',
                        'FR',
                        'GE',
                        'DE',
                        'GR',
                        'GT',
                        'HN',
                        'HK',
                        'HU',
                        'IS',
                        'IN',
                        'ID',
                        'IR',
                        'IE',
                        'IL',
                        'IT',
                        'JM',
                        'JP',
                        'JO',
                        'KZ',
                        'KE',
                        'KP',
                        'KR',
                        'KW',
                        'LV',
                        'LB',
                        'LI',
                        'LT',
                        'LU',
                        'MO',
                        'MK',
                        'MY',
                        'MT',
                        'MX',
                        'MC',
                        'MA',
                        'NP',
                        'NL',
                        'AN',
                        'NZ',
                        'NO',
                        'OM',
                        'PK',
                        'PA',
                        'PG',
                        'PE',
                        'PH',
                        'PL',
                        'PT',
                        'PR',
                        'QA',
                        'RO',
                        'RU',
                        'SA',
                        'SG',
                        'SK',
                        'SI',
                        'ZA',
                        'ES',
                        'LK',
                        'SE',
                        'CH',
                        'SY',
                        'TW',
                        'TH',
                        'TT',
                        'TN',
                        'TR',
                        'AE',
                        'UA',
                        'GB',
                        'US',
                        'PS',
                        'UY',
                        'UZ',
                        'VE',
                        'VN',
                        'YE',
                        'ZW',
                        'NA',
                        'KH',
                        'TZ',
                        'SD',
                        'AO',
                        'RW',
                        'MZ',
                        'RS',
                        'ME',
                        'BB',
                        'GD',
                        'GL',
                        'GU',
                        'PY',
                        'HT',
                        'AW',
                        'MM',
                        'ZB'
                    ],
                    'type': 'str'
                },
                'ble-profile': {
                    'required': False,
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'control-message-offload': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'ebp-frame',
                        'aeroscout-tag',
                        'ap-list',
                        'sta-list',
                        'sta-cap-list',
                        'stats',
                        'aeroscout-mu',
                        'sta-health'
                    ]
                },
                'deny-mac-list': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'mac': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'dtls-in-kernel': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dtls-policy': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'clear-text',
                        'dtls-enabled',
                        'ipsec-vpn'
                    ]
                },
                'energy-efficient-ethernet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ext-info-enable': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'handoff-roaming': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'handoff-rssi': {
                    'required': False,
                    'type': 'int'
                },
                'handoff-sta-thresh': {
                    'required': False,
                    'type': 'int'
                },
                'ip-fragment-preventing': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'tcp-mss-adjust',
                        'icmp-unreachable'
                    ]
                },
                'led-schedules': {
                    'required': False,
                    'type': 'str'
                },
                'led-state': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'lldp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'login-passwd': {
                    'required': False,
                    'type': 'str'
                },
                'login-passwd-change': {
                    'required': False,
                    'choices': [
                        'no',
                        'yes',
                        'default'
                    ],
                    'type': 'str'
                },
                'max-clients': {
                    'required': False,
                    'type': 'int'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'poe-mode': {
                    'required': False,
                    'choices': [
                        'auto',
                        '8023af',
                        '8023at',
                        'power-adapter'
                    ],
                    'type': 'str'
                },
                'split-tunneling-acl': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'dest-ip': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'split-tunneling-acl-local-ap-subnet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'split-tunneling-acl-path': {
                    'required': False,
                    'choices': [
                        'tunnel',
                        'local'
                    ],
                    'type': 'str'
                },
                'tun-mtu-downlink': {
                    'required': False,
                    'type': 'int'
                },
                'tun-mtu-uplink': {
                    'required': False,
                    'type': 'int'
                },
                'wan-port-mode': {
                    'required': False,
                    'choices': [
                        'wan-lan',
                        'wan-only'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
