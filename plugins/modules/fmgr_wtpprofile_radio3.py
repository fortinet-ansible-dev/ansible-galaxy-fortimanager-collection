#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
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
module: fmgr_wtpprofile_radio3
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    wtpprofile_radio3:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            airtime-fairness:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            amsdu:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-handoff:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-addr:
                type: str
                description: no description
            ap-sniffer-bufsize:
                type: int
                description: no description
            ap-sniffer-chan:
                type: int
                description: no description
            ap-sniffer-ctl:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-data:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-beacon:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-other:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ap-sniffer-mgmt-probe:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auto-power-high:
                type: int
                description: no description
            auto-power-level:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auto-power-low:
                type: int
                description: no description
            band:
                type: str
                description: no description
                choices:
                    - '802.11b'
                    - '802.11a'
                    - '802.11g'
                    - '802.11n'
                    - '802.11ac'
                    - '802.11n-5G'
                    - '802.11ax-5G'
                    - '802.11ax'
                    - '802.11g-only'
                    - '802.11n-only'
                    - '802.11n,g-only'
                    - '802.11ac-only'
                    - '802.11ac,n-only'
                    - '802.11n-5G-only'
                    - '802.11ax-5G-only'
                    - '802.11ax,ac-only'
                    - '802.11ax,ac,n-only'
                    - '802.11ax-only'
                    - '802.11ax,n-only'
                    - '802.11ax,n,g-only'
                    - '802.11ac-2G'
            bandwidth-admission-control:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            bandwidth-capacity:
                type: int
                description: no description
            beacon-interval:
                type: int
                description: no description
            call-admission-control:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            call-capacity:
                type: int
                description: no description
            channel:
                description: description
                type: str
            channel-bonding:
                type: str
                description: no description
                choices:
                    - '80MHz'
                    - '40MHz'
                    - '20MHz'
                    - '160MHz'
            channel-utilization:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            coexistence:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            darrp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dtim:
                type: int
                description: no description
            frag-threshold:
                type: int
                description: no description
            frequency-handoff:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            max-clients:
                type: int
                description: no description
            max-distance:
                type: int
                description: no description
            mode:
                type: str
                description: no description
                choices:
                    - 'disabled'
                    - 'ap'
                    - 'monitor'
                    - 'sniffer'
                    - 'sam'
            power-level:
                type: int
                description: no description
            powersave-optimize:
                description: description
                type: list
                choices:
                 - tim
                 - ac-vo
                 - no-obss-scan
                 - no-11b-rate
                 - client-rate-follow
            protection-mode:
                type: str
                description: no description
                choices:
                    - 'rtscts'
                    - 'ctsonly'
                    - 'disable'
            radio-id:
                type: int
                description: no description
            rts-threshold:
                type: int
                description: no description
            short-guard-interval:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            spectrum-analysis:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'scan-only'
            transmit-optimize:
                description: description
                type: list
                choices:
                 - disable
                 - power-save
                 - aggr-limit
                 - retry-limit
                 - send-bar
            vap-all:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'tunnel'
                    - 'bridge'
                    - 'manual'
            vaps:
                type: str
                description: no description
            wids-profile:
                type: str
                description: no description
            band-5g-type:
                type: str
                description: no description
                choices:
                    - '5g-full'
                    - '5g-high'
                    - '5g-low'
            zero-wait-dfs:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            vap1:
                type: str
                description: no description
            vap2:
                type: str
                description: no description
            vap3:
                type: str
                description: no description
            vap4:
                type: str
                description: no description
            vap5:
                type: str
                description: no description
            vap6:
                type: str
                description: no description
            vap7:
                type: str
                description: no description
            vap8:
                type: str
                description: no description
            bss-color:
                type: int
                description: no description
            auto-power-target:
                type: str
                description: no description
            drma:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            drma-sensitivity:
                type: str
                description: no description
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
            iperf-protocol:
                type: str
                description: no description
                choices:
                    - 'udp'
                    - 'tcp'
            iperf-server-port:
                type: int
                description: no description
            power-mode:
                type: str
                description: no description
                choices:
                    - 'dBm'
                    - 'percentage'
            power-value:
                type: int
                description: no description
            sam-bssid:
                type: str
                description: no description
            sam-captive-portal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sam-password:
                description: description
                type: str
            sam-report-intv:
                type: int
                description: no description
            sam-security-type:
                type: str
                description: no description
                choices:
                    - 'open'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
            sam-server:
                type: str
                description: no description
            sam-ssid:
                type: str
                description: no description
            sam-test:
                type: str
                description: no description
                choices:
                    - 'ping'
                    - 'iperf'
            sam-username:
                type: str
                description: no description
            arrp-profile:
                type: str
                description: no description
            bss-color-mode:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - 'static'
            sam-cwp-failure-string:
                type: str
                description: no description
            sam-cwp-match-string:
                type: str
                description: no description
            sam-cwp-password:
                description: description
                type: str
            sam-cwp-success-string:
                type: str
                description: no description
            sam-cwp-test-url:
                type: str
                description: no description
            sam-cwp-username:
                type: str
                description: no description
            sam-server-fqdn:
                type: str
                description: no description
            sam-server-ip:
                type: str
                description: no description
            sam-server-type:
                type: str
                description: no description
                choices:
                    - 'ip'
                    - 'fqdn'

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
    - name: no description
      fmgr_wtpprofile_radio3:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wtp-profile: <your own value>
         wtpprofile_radio3:
            airtime-fairness: <value in [disable, enable]>
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
            channel-bonding: <value in [80MHz, 40MHz, 20MHz, ...]>
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
            spectrum-analysis: <value in [disable, enable, scan-only]>
            transmit-optimize:
              - disable
              - power-save
              - aggr-limit
              - retry-limit
              - send-bar
            vap-all: <value in [disable, enable, tunnel, ...]>
            vaps: <value of string>
            wids-profile: <value of string>
            band-5g-type: <value in [5g-full, 5g-high, 5g-low]>
            zero-wait-dfs: <value in [disable, enable]>
            vap1: <value of string>
            vap2: <value of string>
            vap3: <value of string>
            vap4: <value of string>
            vap5: <value of string>
            vap6: <value of string>
            vap7: <value of string>
            vap8: <value of string>
            bss-color: <value of integer>
            auto-power-target: <value of string>
            drma: <value in [disable, enable]>
            drma-sensitivity: <value in [low, medium, high]>
            iperf-protocol: <value in [udp, tcp]>
            iperf-server-port: <value of integer>
            power-mode: <value in [dBm, percentage]>
            power-value: <value of integer>
            sam-bssid: <value of string>
            sam-captive-portal: <value in [disable, enable]>
            sam-password: <value of string>
            sam-report-intv: <value of integer>
            sam-security-type: <value in [open, wpa-personal, wpa-enterprise]>
            sam-server: <value of string>
            sam-ssid: <value of string>
            sam-test: <value in [ping, iperf]>
            sam-username: <value of string>
            arrp-profile: <value of string>
            bss-color-mode: <value in [auto, static]>
            sam-cwp-failure-string: <value of string>
            sam-cwp-match-string: <value of string>
            sam-cwp-password: <value of string>
            sam-cwp-success-string: <value of string>
            sam-cwp-test-url: <value of string>
            sam-cwp-username: <value of string>
            sam-server-fqdn: <value of string>
            sam-server-ip: <value of string>
            sam-server-type: <value in [ip, fqdn]>

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
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3',
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3/{radio-3}',
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3/{radio-3}'
    ]

    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
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
        'wtpprofile_radio3': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'airtime-fairness': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'amsdu': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-handoff': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-addr': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ap-sniffer-bufsize': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ap-sniffer-chan': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ap-sniffer-ctl': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-data': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-beacon': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-other': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ap-sniffer-mgmt-probe': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-power-high': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'auto-power-level': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-power-low': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'band': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '802.11b',
                        '802.11a',
                        '802.11g',
                        '802.11n',
                        '802.11ac',
                        '802.11n-5G',
                        '802.11ax-5G',
                        '802.11ax',
                        '802.11g-only',
                        '802.11n-only',
                        '802.11n,g-only',
                        '802.11ac-only',
                        '802.11ac,n-only',
                        '802.11n-5G-only',
                        '802.11ax-5G-only',
                        '802.11ax,ac-only',
                        '802.11ax,ac,n-only',
                        '802.11ax-only',
                        '802.11ax,n-only',
                        '802.11ax,n,g-only',
                        '802.11ac-2G'
                    ],
                    'type': 'str'
                },
                'bandwidth-admission-control': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'bandwidth-capacity': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'beacon-interval': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'call-admission-control': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'call-capacity': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'channel': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'channel-bonding': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '80MHz',
                        '40MHz',
                        '20MHz',
                        '160MHz'
                    ],
                    'type': 'str'
                },
                'channel-utilization': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'coexistence': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'darrp': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dtim': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'frag-threshold': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'frequency-handoff': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'max-clients': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'max-distance': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'mode': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disabled',
                        'ap',
                        'monitor',
                        'sniffer',
                        'sam'
                    ],
                    'type': 'str'
                },
                'power-level': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'powersave-optimize': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
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
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'rtscts',
                        'ctsonly',
                        'disable'
                    ],
                    'type': 'str'
                },
                'radio-id': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'rts-threshold': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'short-guard-interval': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spectrum-analysis': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'scan-only'
                    ],
                    'type': 'str'
                },
                'transmit-optimize': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
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
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'tunnel',
                        'bridge',
                        'manual'
                    ],
                    'type': 'str'
                },
                'vaps': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wids-profile': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'band-5g-type': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '5g-full',
                        '5g-high',
                        '5g-low'
                    ],
                    'type': 'str'
                },
                'zero-wait-dfs': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'vap1': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap2': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap3': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap4': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap5': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap6': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap7': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vap8': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'bss-color': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'auto-power-target': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'drma': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'drma-sensitivity': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'low',
                        'medium',
                        'high'
                    ],
                    'type': 'str'
                },
                'iperf-protocol': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'udp',
                        'tcp'
                    ],
                    'type': 'str'
                },
                'iperf-server-port': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'power-mode': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'dBm',
                        'percentage'
                    ],
                    'type': 'str'
                },
                'power-value': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'sam-bssid': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-captive-portal': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sam-password': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-report-intv': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'sam-security-type': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'open',
                        'wpa-personal',
                        'wpa-enterprise'
                    ],
                    'type': 'str'
                },
                'sam-server': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'sam-ssid': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-test': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'ping',
                        'iperf'
                    ],
                    'type': 'str'
                },
                'sam-username': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'arrp-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'bss-color-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'auto',
                        'static'
                    ],
                    'type': 'str'
                },
                'sam-cwp-failure-string': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-cwp-match-string': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-cwp-password': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-cwp-success-string': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-cwp-test-url': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-cwp-username': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-server-fqdn': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-server-ip': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sam-server-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'ip',
                        'fqdn'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_radio3'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
