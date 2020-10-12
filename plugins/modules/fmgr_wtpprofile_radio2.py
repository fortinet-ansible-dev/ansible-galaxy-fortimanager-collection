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
module: fmgr_wtpprofile_radio2
short_description: Configuration options for radio 2.
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
    wtp-profile:
        description: the parameter (wtp-profile) in requested url
        type: str
        required: true
    wtpprofile_radio2:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            amsdu:
                type: str
                description: 'Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-handoff:
                type: str
                description: 'Enable/disable AP handoff of clients to other APs (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-addr:
                type: str
                description: 'MAC address to monitor.'
            ap-sniffer-bufsize:
                type: int
                description: 'Sniffer buffer size (1 - 32 MB, default = 16).'
            ap-sniffer-chan:
                type: int
                description: 'Channel on which to operate the sniffer (default = 6).'
            ap-sniffer-ctl:
                type: str
                description: 'Enable/disable sniffer on WiFi control frame (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-data:
                type: str
                description: 'Enable/disable sniffer on WiFi data frame (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-beacon:
                type: str
                description: 'Enable/disable sniffer on WiFi management Beacon frames (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-other:
                type: str
                description: 'Enable/disable sniffer on WiFi management other frames  (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-probe:
                type: str
                description: 'Enable/disable sniffer on WiFi management probe frames (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            auto-power-high:
                type: int
                description: 'Automatic transmit power high limit in dBm (the actual range of transmit power depends on the AP platform type).'
            auto-power-level:
                type: str
                description: 'Enable/disable automatic power-level adjustment to prevent co-channel interference (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            auto-power-low:
                type: int
                description: 'Automatic transmission power low limit in dBm (the actual range of transmit power depends on the AP platform type).'
            band:
                type: str
                description: 'WiFi band that Radio 2 operates on.'
                choices:
                    - '802.11b'
                    - '802.11a'
                    - '802.11g'
                    - '802.11n'
                    - '802.11ac'
                    - '802.11n-5G'
                    - '802.11g-only'
                    - '802.11n-only'
                    - '802.11n,g-only'
                    - '802.11ac-only'
                    - '802.11ac,n-only'
                    - '802.11n-5G-only'
            bandwidth-admission-control:
                type: str
                description: 'Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireles...'
                choices:
                    - 'disable'
                    - 'enable'
            bandwidth-capacity:
                type: int
                description: 'Maximum bandwidth capacity allowed (1 - 600000 Kbps, default = 2000).'
            beacon-interval:
                type: int
                description: 'Beacon interval. The time between beacon frames in msec (the actual range of beacon interval depends on the AP platform type, ...'
            call-admission-control:
                type: str
                description: 'Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are ...'
                choices:
                    - 'disable'
                    - 'enable'
            call-capacity:
                type: int
                description: 'Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60, default = 10).'
            channel:
                description: no description
                type: str
            channel-bonding:
                type: str
                description: 'Channel bandwidth: 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                choices:
                    - 'disable'
                    - 'enable'
                    - '80MHz'
                    - '40MHz'
                    - '20MHz'
            channel-utilization:
                type: str
                description: 'Enable/disable measuring channel utilization.'
                choices:
                    - 'disable'
                    - 'enable'
            coexistence:
                type: str
                description: 'Enable/disable allowing both HT20 and HT40 on the same radio (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            darrp:
                type: str
                description: 'Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optim...'
                choices:
                    - 'disable'
                    - 'enable'
            dtim:
                type: int
                description: 'DTIM interval. The frequency to transmit Delivery Traffic Indication Message (or Map) (DTIM) messages (1 - 255, default = 1). ...'
            frag-threshold:
                type: int
                description: 'Maximum packet size that can be sent without fragmentation (800 - 2346 bytes, default = 2346).'
            frequency-handoff:
                type: str
                description: 'Enable/disable frequency handoff of clients to other channels (default = disable).'
                choices:
                    - 'disable'
                    - 'enable'
            max-clients:
                type: int
                description: 'Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.'
            max-distance:
                type: int
                description: 'Maximum expected distance between the AP and clients (0 - 54000 m, default = 0).'
            mode:
                type: str
                description: 'Mode of radio 2. Radio 2 can be disabled, configured as an access point, a rogue AP monitor, or a sniffer.'
                choices:
                    - 'disabled'
                    - 'ap'
                    - 'monitor'
                    - 'sniffer'
            power-level:
                type: int
                description: 'Radio power level as a percentage of the maximum transmit power (0 - 100, default = 100).'
            powersave-optimize:
                description: no description
                type: list
                choices:
                 - tim
                 - ac-vo
                 - no-obss-scan
                 - no-11b-rate
                 - client-rate-follow
            protection-mode:
                type: str
                description: 'Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).'
                choices:
                    - 'rtscts'
                    - 'ctsonly'
                    - 'disable'
            radio-id:
                type: int
                description: no description
            rts-threshold:
                type: int
                description: 'Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes, defa...'
            short-guard-interval:
                type: str
                description: 'Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.'
                choices:
                    - 'disable'
                    - 'enable'
            spectrum-analysis:
                type: str
                description: 'Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.'
                choices:
                    - 'disable'
                    - 'enable'
            transmit-optimize:
                description: no description
                type: list
                choices:
                 - disable
                 - power-save
                 - aggr-limit
                 - retry-limit
                 - send-bar
            vap-all:
                type: str
                description: 'Enable/disable the automatic inheritance of all Virtual Access Points (VAPs) (default = enable).'
                choices:
                    - 'disable'
                    - 'enable'
            vaps:
                type: str
                description: 'Manually selected list of Virtual Access Points (VAPs).'
            wids-profile:
                type: str
                description: 'Wireless Intrusion Detection System (WIDS) profile name to assign to the radio.'

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
    - name: Configuration options for radio 2.
      fmgr_wtpprofile_radio2:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wtp-profile: <your own value>
         wtpprofile_radio2:
            amsdu: <value in [disable, enable]>
            ap-handoff: <value in [disable, enable]>
            ap-sniffer-addr: <value of string>
            ap-sniffer-bufsize: <value of integer>
            ap-sniffer-chan: <value of integer>
            ap-sniffer-ctl: <value in [disable, enable]>
            ap-sniffer-data: <value in [disable, enable]>
            ap-sniffer-mgmt-beacon: <value in [disable, enable]>
            ap-sniffer-mgmt-other: <value in [disable, enable]>
            ap-sniffer-mgmt-probe: <value in [disable, enable]>
            auto-power-high: <value of integer>
            auto-power-level: <value in [disable, enable]>
            auto-power-low: <value of integer>
            band: <value in [802.11b, 802.11a, 802.11g, ...]>
            bandwidth-admission-control: <value in [disable, enable]>
            bandwidth-capacity: <value of integer>
            beacon-interval: <value of integer>
            call-admission-control: <value in [disable, enable]>
            call-capacity: <value of integer>
            channel: <value of string>
            channel-bonding: <value in [disable, enable, 80MHz, ...]>
            channel-utilization: <value in [disable, enable]>
            coexistence: <value in [disable, enable]>
            darrp: <value in [disable, enable]>
            dtim: <value of integer>
            frag-threshold: <value of integer>
            frequency-handoff: <value in [disable, enable]>
            max-clients: <value of integer>
            max-distance: <value of integer>
            mode: <value in [disabled, ap, monitor, ...]>
            power-level: <value of integer>
            powersave-optimize:
              - tim
              - ac-vo
              - no-obss-scan
              - no-11b-rate
              - client-rate-follow
            protection-mode: <value in [rtscts, ctsonly, disable]>
            radio-id: <value of integer>
            rts-threshold: <value of integer>
            short-guard-interval: <value in [disable, enable]>
            spectrum-analysis: <value in [disable, enable]>
            transmit-optimize:
              - disable
              - power-save
              - aggr-limit
              - retry-limit
              - send-bar
            vap-all: <value in [disable, enable]>
            vaps: <value of string>
            wids-profile: <value of string>

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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2/{radio-2}',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2/{radio-2}'
    ]

    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'wtp-profile': {
            'required': True,
            'type': 'str'
        },
        'wtpprofile_radio2': {
            'required': False,
            'type': 'dict',
            'options': {
                'amsdu': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-handoff': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-addr': {
                    'required': False,
                    'type': 'str'
                },
                'ap-sniffer-bufsize': {
                    'required': False,
                    'type': 'int'
                },
                'ap-sniffer-chan': {
                    'required': False,
                    'type': 'int'
                },
                'ap-sniffer-ctl': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-data': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-beacon': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-other': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-probe': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-power-high': {
                    'required': False,
                    'type': 'int'
                },
                'auto-power-level': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-power-low': {
                    'required': False,
                    'type': 'int'
                },
                'band': {
                    'required': False,
                    'choices': [
                        '802.11b',
                        '802.11a',
                        '802.11g',
                        '802.11n',
                        '802.11ac',
                        '802.11n-5G',
                        '802.11g-only',
                        '802.11n-only',
                        '802.11n,g-only',
                        '802.11ac-only',
                        '802.11ac,n-only',
                        '802.11n-5G-only'
                    ],
                    'type': 'str'
                },
                'bandwidth-admission-control': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'bandwidth-capacity': {
                    'required': False,
                    'type': 'int'
                },
                'beacon-interval': {
                    'required': False,
                    'type': 'int'
                },
                'call-admission-control': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'call-capacity': {
                    'required': False,
                    'type': 'int'
                },
                'channel': {
                    'required': False,
                    'type': 'str'
                },
                'channel-bonding': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        '80MHz',
                        '40MHz',
                        '20MHz'
                    ],
                    'type': 'str'
                },
                'channel-utilization': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'coexistence': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'darrp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dtim': {
                    'required': False,
                    'type': 'int'
                },
                'frag-threshold': {
                    'required': False,
                    'type': 'int'
                },
                'frequency-handoff': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'max-clients': {
                    'required': False,
                    'type': 'int'
                },
                'max-distance': {
                    'required': False,
                    'type': 'int'
                },
                'mode': {
                    'required': False,
                    'choices': [
                        'disabled',
                        'ap',
                        'monitor',
                        'sniffer'
                    ],
                    'type': 'str'
                },
                'power-level': {
                    'required': False,
                    'type': 'int'
                },
                'powersave-optimize': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'tim',
                        'ac-vo',
                        'no-obss-scan',
                        'no-11b-rate',
                        'client-rate-follow'
                    ]
                },
                'protection-mode': {
                    'required': False,
                    'choices': [
                        'rtscts',
                        'ctsonly',
                        'disable'
                    ],
                    'type': 'str'
                },
                'radio-id': {
                    'required': False,
                    'type': 'int'
                },
                'rts-threshold': {
                    'required': False,
                    'type': 'int'
                },
                'short-guard-interval': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spectrum-analysis': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'transmit-optimize': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'disable',
                        'power-save',
                        'aggr-limit',
                        'retry-limit',
                        'send-bar'
                    ]
                },
                'vap-all': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'vaps': {
                    'required': False,
                    'type': 'str'
                },
                'wids-profile': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_radio2'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
