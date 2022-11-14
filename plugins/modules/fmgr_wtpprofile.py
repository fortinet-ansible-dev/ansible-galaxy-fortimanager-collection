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
module: fmgr_wtpprofile
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
                description: no description
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
                    - 'CF'
                    - 'BS'
                    - 'VC'
                    - 'MV'
                    - 'SN'
                    - 'CI'
                    - 'GH'
                    - 'MW'
                    - 'UG'
                    - 'BF'
                    - 'KY'
                    - 'TC'
                    - 'TM'
                    - 'VU'
                    - 'FM'
                    - 'GY'
                    - 'KN'
                    - 'LC'
                    - 'CX'
                    - 'AF'
                    - 'CM'
                    - 'ML'
                    - 'BJ'
                    - 'MG'
                    - 'TD'
                    - 'BW'
                    - 'LY'
                    - 'LS'
                    - 'MU'
                    - 'SL'
                    - 'NE'
                    - 'TG'
                    - 'RE'
                    - 'MD'
                    - 'BM'
                    - 'VI'
                    - 'PM'
                    - 'MF'
                    - 'IM'
                    - 'FO'
                    - 'GI'
                    - 'LA'
                    - 'WF'
                    - 'MH'
                    - 'BT'
                    - 'PF'
                    - 'NI'
                    - 'GF'
                    - 'AS'
                    - 'MP'
                    - 'PW'
                    - 'GP'
                    - 'ET'
                    - 'SR'
                    - 'DM'
                    - 'MQ'
                    - 'YT'
                    - 'BL'
                    - 'ZM'
                    - 'CG'
                    - 'CD'
                    - 'MR'
                    - 'IQ'
                    - 'FJ'
                    - '--'
            ble-profile:
                type: str
                description: no description
            comment:
                type: str
                description: no description
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
                 - spectral-analysis
            deny-mac-list:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: no description
                    mac:
                        type: str
                        description: no description
            dtls-in-kernel:
                type: str
                description: no description
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
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ext-info-enable:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            handoff-roaming:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            handoff-rssi:
                type: int
                description: no description
            handoff-sta-thresh:
                type: int
                description: no description
            ip-fragment-preventing:
                description: no description
                type: list
                choices:
                 - tcp-mss-adjust
                 - icmp-unreachable
            led-schedules:
                type: str
                description: no description
            led-state:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            lldp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            login-passwd:
                description: no description
                type: str
            login-passwd-change:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            max-clients:
                type: int
                description: no description
            name:
                type: str
                description: no description
            poe-mode:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - '8023af'
                    - '8023at'
                    - 'power-adapter'
                    - 'full'
                    - 'high'
                    - 'low'
            split-tunneling-acl:
                description: no description
                type: list
                suboptions:
                    dest-ip:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
            split-tunneling-acl-local-ap-subnet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-acl-path:
                type: str
                description: no description
                choices:
                    - 'tunnel'
                    - 'local'
            tun-mtu-downlink:
                type: int
                description: no description
            tun-mtu-uplink:
                type: int
                description: no description
            wan-port-mode:
                type: str
                description: no description
                choices:
                    - 'wan-lan'
                    - 'wan-only'
            snmp:
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
            apcfg-profile:
                type: str
                description: no description
            frequency-handoff:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            lan:
                description: no description
                type: dict
                required: false
                suboptions:
                    port-esl-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port-esl-ssid:
                        type: str
                        description: no description
                    port-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port-ssid:
                        type: str
                        description: no description
                    port1-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port1-ssid:
                        type: str
                        description: no description
                    port2-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port2-ssid:
                        type: str
                        description: no description
                    port3-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port3-ssid:
                        type: str
                        description: no description
                    port4-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port4-ssid:
                        type: str
                        description: no description
                    port5-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port5-ssid:
                        type: str
                        description: no description
                    port6-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port6-ssid:
                        type: str
                        description: no description
                    port7-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port7-ssid:
                        type: str
                        description: no description
                    port8-mode:
                        type: str
                        description: no description
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port8-ssid:
                        type: str
                        description: no description
            lbs:
                description: no description
                type: dict
                required: false
                suboptions:
                    aeroscout:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout-ap-mac:
                        type: str
                        description: no description
                        choices:
                            - 'bssid'
                            - 'board-mac'
                    aeroscout-mmu-report:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout-mu:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout-mu-factor:
                        type: int
                        description: no description
                    aeroscout-mu-timeout:
                        type: int
                        description: no description
                    aeroscout-server-ip:
                        type: str
                        description: no description
                    aeroscout-server-port:
                        type: int
                        description: no description
                    ekahau-blink-mode:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ekahau-tag:
                        type: str
                        description: no description
                    erc-server-ip:
                        type: str
                        description: no description
                    erc-server-port:
                        type: int
                        description: no description
                    fortipresence:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'enable2'
                            - 'foreign'
                            - 'both'
                    fortipresence-ble:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence-frequency:
                        type: int
                        description: no description
                    fortipresence-port:
                        type: int
                        description: no description
                    fortipresence-project:
                        type: str
                        description: no description
                    fortipresence-rogue:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence-secret:
                        description: no description
                        type: str
                    fortipresence-server:
                        type: str
                        description: no description
                    fortipresence-unassoc:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    station-locate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence-server-addr-type:
                        type: str
                        description: no description
                        choices:
                            - 'fqdn'
                            - 'ipv4'
                    fortipresence-server-fqdn:
                        type: str
                        description: no description
            platform:
                description: no description
                type: dict
                required: false
                suboptions:
                    ddscan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    mode:
                        type: str
                        description: no description
                        choices:
                            - 'dual-5G'
                            - 'single-5G'
                    type:
                        type: str
                        description: no description
                        choices:
                            - '30B-50B'
                            - '60B'
                            - '80CM-81CM'
                            - '220A'
                            - '220B'
                            - '210B'
                            - '60C'
                            - '222B'
                            - '112B'
                            - '320B'
                            - '11C'
                            - '14C'
                            - '223B'
                            - '28C'
                            - '320C'
                            - '221C'
                            - '25D'
                            - '222C'
                            - '224D'
                            - '214B'
                            - '21D'
                            - '24D'
                            - '112D'
                            - '223C'
                            - '321C'
                            - 'C220C'
                            - 'C225C'
                            - 'S321C'
                            - 'S323C'
                            - 'FWF'
                            - 'S311C'
                            - 'S313C'
                            - 'AP-11N'
                            - 'S322C'
                            - 'S321CR'
                            - 'S322CR'
                            - 'S323CR'
                            - 'S421E'
                            - 'S422E'
                            - 'S423E'
                            - '421E'
                            - '423E'
                            - 'C221E'
                            - 'C226E'
                            - 'C23JD'
                            - 'C24JE'
                            - 'C21D'
                            - 'U421E'
                            - 'U423E'
                            - '221E'
                            - '222E'
                            - '223E'
                            - 'S221E'
                            - 'S223E'
                            - 'U221EV'
                            - 'U223EV'
                            - 'U321EV'
                            - 'U323EV'
                            - '224E'
                            - 'U422EV'
                            - 'U24JEV'
                            - '321E'
                            - 'U431F'
                            - 'U433F'
                            - '231E'
                            - '431F'
                            - '433F'
                            - '231F'
                            - '432F'
                            - '234F'
                            - '23JF'
                            - 'U231F'
                            - '831F'
                            - 'U234F'
                            - 'U432F'
                    _local_platform_str:
                        type: str
                        description: no description
            radio-1:
                description: no description
                type: dict
                required: false
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
                    auto-power-target:
                        type: str
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
                            - '802.11ac-2G'
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
                    band-5g-type:
                        type: str
                        description: no description
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
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
                    bss-color:
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
                        description: no description
                        type: str
                    channel-bonding:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                    dtim:
                        type: int
                        description: no description
                    frag-threshold:
                        type: int
                        description: no description
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
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
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
                    vaps:
                        type: str
                        description: no description
                    wids-profile:
                        type: str
                        description: no description
                    zero-wait-dfs:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                        description: no description
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
            radio-2:
                description: no description
                type: dict
                required: false
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
                    auto-power-target:
                        type: str
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
                            - '802.11ac-2G'
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
                    band-5g-type:
                        type: str
                        description: no description
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
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
                    bss-color:
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
                        description: no description
                        type: str
                    channel-bonding:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                    dtim:
                        type: int
                        description: no description
                    frag-threshold:
                        type: int
                        description: no description
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
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
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
                    vaps:
                        type: str
                        description: no description
                    wids-profile:
                        type: str
                        description: no description
                    zero-wait-dfs:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                        description: no description
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
            radio-3:
                description: no description
                type: dict
                required: false
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
                    auto-power-target:
                        type: str
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
                            - '802.11ac-2G'
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
                    band-5g-type:
                        type: str
                        description: no description
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
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
                    bss-color:
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
                        description: no description
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
                    dtim:
                        type: int
                        description: no description
                    frag-threshold:
                        type: int
                        description: no description
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
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
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
                    vaps:
                        type: str
                        description: no description
                    wids-profile:
                        type: str
                        description: no description
                    zero-wait-dfs:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                        description: no description
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
            radio-4:
                description: no description
                type: dict
                required: false
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
                    auto-power-target:
                        type: str
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
                            - '802.11ac-2G'
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
                    band-5g-type:
                        type: str
                        description: no description
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
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
                    bss-color:
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
                        description: no description
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
                    dtim:
                        type: int
                        description: no description
                    frag-threshold:
                        type: int
                        description: no description
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
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'disabled'
                            - 'sam'
                    power-level:
                        type: int
                        description: no description
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
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
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
                    vaps:
                        type: str
                        description: no description
                    wids-profile:
                        type: str
                        description: no description
                    zero-wait-dfs:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
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
                        description: no description
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
            console-login:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            esl-ses-dongle:
                description: no description
                type: dict
                required: false
                suboptions:
                    apc-addr-type:
                        type: str
                        description: no description
                        choices:
                            - 'fqdn'
                            - 'ip'
                    apc-fqdn:
                        type: str
                        description: no description
                    apc-ip:
                        type: str
                        description: no description
                    apc-port:
                        type: int
                        description: no description
                    coex-level:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                    compliance-level:
                        type: str
                        description: no description
                        choices:
                            - 'compliance-level-2'
                    esl-channel:
                        type: str
                        description: no description
                        choices:
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '127'
                            - '-1'
                    output-power:
                        type: str
                        description: no description
                        choices:
                            - 'a'
                            - 'b'
                            - 'c'
                            - 'd'
                            - 'e'
                            - 'f'
                            - 'g'
                            - 'h'
                    scd-enable:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    tls-cert-verification:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    tls-fqdn-verification:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            indoor-outdoor-deployment:
                type: str
                description: no description
                choices:
                    - 'platform-determined'
                    - 'outdoor'
                    - 'indoor'
            syslog-profile:
                type: str
                description: no description
            wan-port-auth:
                type: str
                description: no description
                choices:
                    - 'none'
                    - '802.1x'
            wan-port-auth-methods:
                type: str
                description: no description
                choices:
                    - 'all'
                    - 'EAP-FAST'
                    - 'EAP-TLS'
                    - 'EAP-PEAP'
            wan-port-auth-password:
                description: description
                type: str
            wan-port-auth-usrname:
                type: str
                description: no description

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
              - spectral-analysis
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
            snmp: <value in [disable, enable]>
            ap-handoff: <value in [disable, enable]>
            apcfg-profile: <value of string>
            frequency-handoff: <value in [disable, enable]>
            lan:
               port-esl-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port-esl-ssid: <value of string>
               port-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port-ssid: <value of string>
               port1-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port1-ssid: <value of string>
               port2-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port2-ssid: <value of string>
               port3-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port3-ssid: <value of string>
               port4-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port4-ssid: <value of string>
               port5-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port5-ssid: <value of string>
               port6-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port6-ssid: <value of string>
               port7-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port7-ssid: <value of string>
               port8-mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
               port8-ssid: <value of string>
            lbs:
               aeroscout: <value in [disable, enable]>
               aeroscout-ap-mac: <value in [bssid, board-mac]>
               aeroscout-mmu-report: <value in [disable, enable]>
               aeroscout-mu: <value in [disable, enable]>
               aeroscout-mu-factor: <value of integer>
               aeroscout-mu-timeout: <value of integer>
               aeroscout-server-ip: <value of string>
               aeroscout-server-port: <value of integer>
               ekahau-blink-mode: <value in [disable, enable]>
               ekahau-tag: <value of string>
               erc-server-ip: <value of string>
               erc-server-port: <value of integer>
               fortipresence: <value in [disable, enable, enable2, ...]>
               fortipresence-ble: <value in [disable, enable]>
               fortipresence-frequency: <value of integer>
               fortipresence-port: <value of integer>
               fortipresence-project: <value of string>
               fortipresence-rogue: <value in [disable, enable]>
               fortipresence-secret: <value of string>
               fortipresence-server: <value of string>
               fortipresence-unassoc: <value in [disable, enable]>
               station-locate: <value in [disable, enable]>
               fortipresence-server-addr-type: <value in [fqdn, ipv4]>
               fortipresence-server-fqdn: <value of string>
            platform:
               ddscan: <value in [disable, enable]>
               mode: <value in [dual-5G, single-5G]>
               type: <value in [30B-50B, 60B, 80CM-81CM, ...]>
               _local_platform_str: <value of string>
            radio-1:
               airtime-fairness: <value in [disable, enable]>
               amsdu: <value in [disable, enable]>
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
               auto-power-target: <value of string>
               band: <value in [802.11b, 802.11a, 802.11g, ...]>
               band-5g-type: <value in [5g-full, 5g-high, 5g-low]>
               bandwidth-admission-control: <value in [disable, enable]>
               bandwidth-capacity: <value of integer>
               beacon-interval: <value of integer>
               bss-color: <value of integer>
               call-admission-control: <value in [disable, enable]>
               call-capacity: <value of integer>
               channel: <value of string>
               channel-bonding: <value in [disable, enable, 80MHz, ...]>
               channel-utilization: <value in [disable, enable]>
               coexistence: <value in [disable, enable]>
               darrp: <value in [disable, enable]>
               drma: <value in [disable, enable]>
               drma-sensitivity: <value in [low, medium, high]>
               dtim: <value of integer>
               frag-threshold: <value of integer>
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
               vap1: <value of string>
               vap2: <value of string>
               vap3: <value of string>
               vap4: <value of string>
               vap5: <value of string>
               vap6: <value of string>
               vap7: <value of string>
               vap8: <value of string>
               vaps: <value of string>
               wids-profile: <value of string>
               zero-wait-dfs: <value in [disable, enable]>
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
            radio-2:
               airtime-fairness: <value in [disable, enable]>
               amsdu: <value in [disable, enable]>
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
               auto-power-target: <value of string>
               band: <value in [802.11b, 802.11a, 802.11g, ...]>
               band-5g-type: <value in [5g-full, 5g-high, 5g-low]>
               bandwidth-admission-control: <value in [disable, enable]>
               bandwidth-capacity: <value of integer>
               beacon-interval: <value of integer>
               bss-color: <value of integer>
               call-admission-control: <value in [disable, enable]>
               call-capacity: <value of integer>
               channel: <value of string>
               channel-bonding: <value in [disable, enable, 80MHz, ...]>
               channel-utilization: <value in [disable, enable]>
               coexistence: <value in [disable, enable]>
               darrp: <value in [disable, enable]>
               drma: <value in [disable, enable]>
               drma-sensitivity: <value in [low, medium, high]>
               dtim: <value of integer>
               frag-threshold: <value of integer>
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
               vap1: <value of string>
               vap2: <value of string>
               vap3: <value of string>
               vap4: <value of string>
               vap5: <value of string>
               vap6: <value of string>
               vap7: <value of string>
               vap8: <value of string>
               vaps: <value of string>
               wids-profile: <value of string>
               zero-wait-dfs: <value in [disable, enable]>
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
            radio-3:
               airtime-fairness: <value in [disable, enable]>
               amsdu: <value in [disable, enable]>
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
               auto-power-target: <value of string>
               band: <value in [802.11b, 802.11a, 802.11g, ...]>
               band-5g-type: <value in [5g-full, 5g-high, 5g-low]>
               bandwidth-admission-control: <value in [disable, enable]>
               bandwidth-capacity: <value of integer>
               beacon-interval: <value of integer>
               bss-color: <value of integer>
               call-admission-control: <value in [disable, enable]>
               call-capacity: <value of integer>
               channel: <value of string>
               channel-bonding: <value in [80MHz, 40MHz, 20MHz, ...]>
               channel-utilization: <value in [disable, enable]>
               coexistence: <value in [disable, enable]>
               darrp: <value in [disable, enable]>
               drma: <value in [disable, enable]>
               drma-sensitivity: <value in [low, medium, high]>
               dtim: <value of integer>
               frag-threshold: <value of integer>
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
               vap1: <value of string>
               vap2: <value of string>
               vap3: <value of string>
               vap4: <value of string>
               vap5: <value of string>
               vap6: <value of string>
               vap7: <value of string>
               vap8: <value of string>
               vaps: <value of string>
               wids-profile: <value of string>
               zero-wait-dfs: <value in [disable, enable]>
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
            radio-4:
               airtime-fairness: <value in [disable, enable]>
               amsdu: <value in [disable, enable]>
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
               auto-power-target: <value of string>
               band: <value in [802.11b, 802.11a, 802.11g, ...]>
               band-5g-type: <value in [5g-full, 5g-high, 5g-low]>
               bandwidth-admission-control: <value in [disable, enable]>
               bandwidth-capacity: <value of integer>
               beacon-interval: <value of integer>
               bss-color: <value of integer>
               call-admission-control: <value in [disable, enable]>
               call-capacity: <value of integer>
               channel: <value of string>
               channel-bonding: <value in [80MHz, 40MHz, 20MHz, ...]>
               channel-utilization: <value in [disable, enable]>
               coexistence: <value in [disable, enable]>
               darrp: <value in [disable, enable]>
               drma: <value in [disable, enable]>
               drma-sensitivity: <value in [low, medium, high]>
               dtim: <value of integer>
               frag-threshold: <value of integer>
               max-clients: <value of integer>
               max-distance: <value of integer>
               mode: <value in [ap, monitor, sniffer, ...]>
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
               vap1: <value of string>
               vap2: <value of string>
               vap3: <value of string>
               vap4: <value of string>
               vap5: <value of string>
               vap6: <value of string>
               vap7: <value of string>
               vap8: <value of string>
               vaps: <value of string>
               wids-profile: <value of string>
               zero-wait-dfs: <value in [disable, enable]>
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
            console-login: <value in [disable, enable]>
            esl-ses-dongle:
               apc-addr-type: <value in [fqdn, ip]>
               apc-fqdn: <value of string>
               apc-ip: <value of string>
               apc-port: <value of integer>
               coex-level: <value in [none]>
               compliance-level: <value in [compliance-level-2]>
               esl-channel: <value in [0, 1, 2, ...]>
               output-power: <value in [a, b, c, ...]>
               scd-enable: <value in [disable, enable]>
               tls-cert-verification: <value in [disable, enable]>
               tls-fqdn-verification: <value in [disable, enable]>
            indoor-outdoor-deployment: <value in [platform-determined, outdoor, indoor]>
            syslog-profile: <value of string>
            wan-port-auth: <value in [none, 802.1x]>
            wan-port-auth-methods: <value in [all, EAP-FAST, EAP-TLS, ...]>
            wan-port-auth-password: <value of string>
            wan-port-auth-usrname: <value of string>

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
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'allowaccess': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                        'https',
                        'ssh',
                        'snmp',
                        'http',
                        'telnet'
                    ]
                },
                'ap-country': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
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
                        'ZB',
                        'CF',
                        'BS',
                        'VC',
                        'MV',
                        'SN',
                        'CI',
                        'GH',
                        'MW',
                        'UG',
                        'BF',
                        'KY',
                        'TC',
                        'TM',
                        'VU',
                        'FM',
                        'GY',
                        'KN',
                        'LC',
                        'CX',
                        'AF',
                        'CM',
                        'ML',
                        'BJ',
                        'MG',
                        'TD',
                        'BW',
                        'LY',
                        'LS',
                        'MU',
                        'SL',
                        'NE',
                        'TG',
                        'RE',
                        'MD',
                        'BM',
                        'VI',
                        'PM',
                        'MF',
                        'IM',
                        'FO',
                        'GI',
                        'LA',
                        'WF',
                        'MH',
                        'BT',
                        'PF',
                        'NI',
                        'GF',
                        'AS',
                        'MP',
                        'PW',
                        'GP',
                        'ET',
                        'SR',
                        'DM',
                        'MQ',
                        'YT',
                        'BL',
                        'ZM',
                        'CG',
                        'CD',
                        'MR',
                        'IQ',
                        'FJ',
                        '--'
                    ],
                    'type': 'str'
                },
                'ble-profile': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'control-message-offload': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                        'ebp-frame',
                        'aeroscout-tag',
                        'ap-list',
                        'sta-list',
                        'sta-cap-list',
                        'stats',
                        'aeroscout-mu',
                        'sta-health',
                        'spectral-analysis'
                    ]
                },
                'deny-mac-list': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
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
                        'mac': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'dtls-in-kernel': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'dtls-policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                        'clear-text',
                        'dtls-enabled',
                        'ipsec-vpn'
                    ]
                },
                'energy-efficient-ethernet': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'ext-info-enable': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'handoff-roaming': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'handoff-rssi': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'handoff-sta-thresh': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'ip-fragment-preventing': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                        'tcp-mss-adjust',
                        'icmp-unreachable'
                    ]
                },
                'led-schedules': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'led-state': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'lldp': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'login-passwd': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'login-passwd-change': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'no',
                        'yes',
                        'default'
                    ],
                    'type': 'str'
                },
                'max-clients': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'poe-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'auto',
                        '8023af',
                        '8023at',
                        'power-adapter',
                        'full',
                        'high',
                        'low'
                    ],
                    'type': 'str'
                },
                'split-tunneling-acl': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'dest-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
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
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'split-tunneling-acl-local-ap-subnet': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'split-tunneling-acl-path': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'tunnel',
                        'local'
                    ],
                    'type': 'str'
                },
                'tun-mtu-downlink': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'tun-mtu-uplink': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
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
                'wan-port-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'wan-lan',
                        'wan-only'
                    ],
                    'type': 'str'
                },
                'snmp': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
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
                'ap-handoff': {
                    'required': False,
                    'revision': {
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
                'apcfg-profile': {
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
                'frequency-handoff': {
                    'required': False,
                    'revision': {
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
                'lan': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'port-esl-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port-esl-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port1-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port1-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port2-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port2-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port3-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port3-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port4-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port4-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port5-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port5-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port6-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port6-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port7-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port7-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port8-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'offline',
                                'bridge-to-wan',
                                'bridge-to-ssid',
                                'nat-to-wan'
                            ],
                            'type': 'str'
                        },
                        'port8-ssid': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'lbs': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'aeroscout': {
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
                        'aeroscout-ap-mac': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'bssid',
                                'board-mac'
                            ],
                            'type': 'str'
                        },
                        'aeroscout-mmu-report': {
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
                        'aeroscout-mu': {
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
                        'aeroscout-mu-factor': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'aeroscout-mu-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'aeroscout-server-ip': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'aeroscout-server-port': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ekahau-blink-mode': {
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
                        'ekahau-tag': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'erc-server-ip': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'erc-server-port': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'fortipresence': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'enable2',
                                'foreign',
                                'both'
                            ],
                            'type': 'str'
                        },
                        'fortipresence-ble': {
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
                        'fortipresence-frequency': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'fortipresence-port': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'fortipresence-project': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'fortipresence-rogue': {
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
                        'fortipresence-secret': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'fortipresence-server': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'fortipresence-unassoc': {
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
                        'station-locate': {
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
                        'fortipresence-server-addr-type': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'fqdn',
                                'ipv4'
                            ],
                            'type': 'str'
                        },
                        'fortipresence-server-fqdn': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'platform': {
                    'required': False,
                    'type': 'dict'
                },
                'radio-1': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {
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
                        'amsdu': {
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
                        'ap-sniffer-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ap-sniffer-bufsize': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-chan': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-ctl': {
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
                        'ap-sniffer-data': {
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
                        'ap-sniffer-mgmt-beacon': {
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
                        'ap-sniffer-mgmt-other': {
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
                        'ap-sniffer-mgmt-probe': {
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
                        'auto-power-high': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'auto-power-level': {
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
                        'auto-power-low': {
                            'required': False,
                            'revision': {
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
                        'band': {
                            'required': False,
                            'revision': {
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
                                '802.11ac-2G',
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
                                '802.11ax,n,g-only'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {
                            'required': False,
                            'revision': {
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
                        'bandwidth-admission-control': {
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
                        'bandwidth-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'beacon-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'bss-color': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'call-admission-control': {
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
                        'call-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'channel': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'channel-bonding': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
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
                        'dtim': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'frag-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-clients': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-distance': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mode': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'powersave-optimize': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'rts-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'short-guard-interval': {
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
                        'spectrum-analysis': {
                            'required': False,
                            'revision': {
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
                        'vap1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap7': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap8': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vaps': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wids-profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'zero-wait-dfs': {
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
                },
                'radio-2': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {
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
                        'amsdu': {
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
                        'ap-sniffer-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ap-sniffer-bufsize': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-chan': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-ctl': {
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
                        'ap-sniffer-data': {
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
                        'ap-sniffer-mgmt-beacon': {
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
                        'ap-sniffer-mgmt-other': {
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
                        'ap-sniffer-mgmt-probe': {
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
                        'auto-power-high': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'auto-power-level': {
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
                        'auto-power-low': {
                            'required': False,
                            'revision': {
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
                        'band': {
                            'required': False,
                            'revision': {
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
                                '802.11ac-2G',
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
                                '802.11ax,n,g-only'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {
                            'required': False,
                            'revision': {
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
                        'bandwidth-admission-control': {
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
                        'bandwidth-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'beacon-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'bss-color': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'call-admission-control': {
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
                        'call-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'channel': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'channel-bonding': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
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
                        'dtim': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'frag-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-clients': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-distance': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mode': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'powersave-optimize': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'rts-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'short-guard-interval': {
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
                        'spectrum-analysis': {
                            'required': False,
                            'revision': {
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
                        'vap1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap7': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap8': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vaps': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wids-profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'zero-wait-dfs': {
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
                },
                'radio-3': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {
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
                        'amsdu': {
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
                        'ap-sniffer-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ap-sniffer-bufsize': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-chan': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-ctl': {
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
                        'ap-sniffer-data': {
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
                        'ap-sniffer-mgmt-beacon': {
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
                        'ap-sniffer-mgmt-other': {
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
                        'ap-sniffer-mgmt-probe': {
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
                        'auto-power-high': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'auto-power-level': {
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
                        'auto-power-low': {
                            'required': False,
                            'revision': {
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
                        'band': {
                            'required': False,
                            'revision': {
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
                                '802.11ac-2G',
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
                                '802.11ax,n,g-only'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {
                            'required': False,
                            'revision': {
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
                        'bandwidth-admission-control': {
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
                        'bandwidth-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'beacon-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'bss-color': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'call-admission-control': {
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
                        'call-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'channel': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'channel-bonding': {
                            'required': False,
                            'revision': {
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
                        'dtim': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'frag-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-clients': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-distance': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mode': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'powersave-optimize': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'rts-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'short-guard-interval': {
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
                        'spectrum-analysis': {
                            'required': False,
                            'revision': {
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
                        'vap1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap7': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap8': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vaps': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wids-profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'zero-wait-dfs': {
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
                },
                'radio-4': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {
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
                        'amsdu': {
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
                        'ap-sniffer-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ap-sniffer-bufsize': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-chan': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ap-sniffer-ctl': {
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
                        'ap-sniffer-data': {
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
                        'ap-sniffer-mgmt-beacon': {
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
                        'ap-sniffer-mgmt-other': {
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
                        'ap-sniffer-mgmt-probe': {
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
                        'auto-power-high': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'auto-power-level': {
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
                        'auto-power-low': {
                            'required': False,
                            'revision': {
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
                        'band': {
                            'required': False,
                            'revision': {
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
                                '802.11ac-2G',
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
                                '802.11ax,n,g-only'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {
                            'required': False,
                            'revision': {
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
                        'bandwidth-admission-control': {
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
                        'bandwidth-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'beacon-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'bss-color': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'call-admission-control': {
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
                        'call-capacity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'channel': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'channel-bonding': {
                            'required': False,
                            'revision': {
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
                        'dtim': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'frag-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-clients': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'max-distance': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'ap',
                                'monitor',
                                'sniffer',
                                'disabled',
                                'sam'
                            ],
                            'type': 'str'
                        },
                        'power-level': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'powersave-optimize': {
                            'required': False,
                            'revision': {
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
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'rts-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'short-guard-interval': {
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
                        'spectrum-analysis': {
                            'required': False,
                            'revision': {
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
                        'vap1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap7': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vap8': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vaps': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wids-profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'zero-wait-dfs': {
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
                },
                'console-login': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'esl-ses-dongle': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'apc-addr-type': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'fqdn',
                                'ip'
                            ],
                            'type': 'str'
                        },
                        'apc-fqdn': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'apc-ip': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'apc-port': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'coex-level': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'none'
                            ],
                            'type': 'str'
                        },
                        'compliance-level': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'compliance-level-2'
                            ],
                            'type': 'str'
                        },
                        'esl-channel': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                '0',
                                '1',
                                '2',
                                '3',
                                '4',
                                '5',
                                '6',
                                '7',
                                '8',
                                '9',
                                '10',
                                '127',
                                '-1'
                            ],
                            'type': 'str'
                        },
                        'output-power': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'a',
                                'b',
                                'c',
                                'd',
                                'e',
                                'f',
                                'g',
                                'h'
                            ],
                            'type': 'str'
                        },
                        'scd-enable': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'tls-cert-verification': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'tls-fqdn-verification': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'indoor-outdoor-deployment': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'platform-determined',
                        'outdoor',
                        'indoor'
                    ],
                    'type': 'str'
                },
                'syslog-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wan-port-auth': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        '802.1x'
                    ],
                    'type': 'str'
                },
                'wan-port-auth-methods': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'all',
                        'EAP-FAST',
                        'EAP-TLS',
                        'EAP-PEAP'
                    ],
                    'type': 'str'
                },
                'wan-port-auth-password': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wan-port-auth-usrname': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
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
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
