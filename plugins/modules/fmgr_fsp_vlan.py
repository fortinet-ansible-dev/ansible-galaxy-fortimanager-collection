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
module: fmgr_fsp_vlan
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
    fsp_vlan:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _dhcp-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auth:
                type: str
                description: no description
                choices:
                    - 'radius'
                    - 'usergroup'
            color:
                type: int
                description: no description
            comments:
                type: str
                description: no description
            dynamic_mapping:
                description: no description
                type: list
                suboptions:
                    _dhcp-status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    _scope:
                        description: no description
                        type: list
                        suboptions:
                            name:
                                type: str
                                description: no description
                            vdom:
                                type: str
                                description: no description
                    dhcp-server:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            auto-configuration:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            auto-managed-status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            conflicted-ip-timeout:
                                type: int
                                description: no description
                            ddns-auth:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'tsig'
                            ddns-key:
                                type: str
                                description: no description
                            ddns-keyname:
                                type: str
                                description: no description
                            ddns-server-ip:
                                type: str
                                description: no description
                            ddns-ttl:
                                type: int
                                description: no description
                            ddns-update:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ddns-update-override:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ddns-zone:
                                type: str
                                description: no description
                            default-gateway:
                                type: str
                                description: no description
                            dhcp-settings-from-fortiipam:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dns-server1:
                                type: str
                                description: no description
                            dns-server2:
                                type: str
                                description: no description
                            dns-server3:
                                type: str
                                description: no description
                            dns-server4:
                                type: str
                                description: no description
                            dns-service:
                                type: str
                                description: no description
                                choices:
                                    - 'default'
                                    - 'specify'
                                    - 'local'
                            domain:
                                type: str
                                description: no description
                            enable:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            exclude-range:
                                description: no description
                                type: list
                                suboptions:
                                    end-ip:
                                        type: str
                                        description: no description
                                    id:
                                        type: int
                                        description: no description
                                    start-ip:
                                        type: str
                                        description: no description
                            filename:
                                type: str
                                description: no description
                            forticlient-on-net-status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                                description: no description
                            ip-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'range'
                                    - 'usrgrp'
                            ip-range:
                                description: no description
                                type: list
                                suboptions:
                                    end-ip:
                                        type: str
                                        description: no description
                                    id:
                                        type: int
                                        description: no description
                                    start-ip:
                                        type: str
                                        description: no description
                            ipsec-lease-hold:
                                type: int
                                description: no description
                            lease-time:
                                type: int
                                description: no description
                            mac-acl-default-action:
                                type: str
                                description: no description
                                choices:
                                    - 'assign'
                                    - 'block'
                            netmask:
                                type: str
                                description: no description
                            next-server:
                                type: str
                                description: no description
                            ntp-server1:
                                type: str
                                description: no description
                            ntp-server2:
                                type: str
                                description: no description
                            ntp-server3:
                                type: str
                                description: no description
                            ntp-service:
                                type: str
                                description: no description
                                choices:
                                    - 'default'
                                    - 'specify'
                                    - 'local'
                            option1:
                                description: no description
                                type: str
                            option2:
                                description: no description
                                type: str
                            option3:
                                description: no description
                                type: str
                            option4:
                                type: str
                                description: no description
                            option5:
                                type: str
                                description: no description
                            option6:
                                type: str
                                description: no description
                            options:
                                description: no description
                                type: list
                                suboptions:
                                    code:
                                        type: int
                                        description: no description
                                    id:
                                        type: int
                                        description: no description
                                    ip:
                                        description: no description
                                        type: str
                                    type:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'hex'
                                            - 'string'
                                            - 'ip'
                                            - 'fqdn'
                                    value:
                                        type: str
                                        description: no description
                            reserved-address:
                                description: no description
                                type: list
                                suboptions:
                                    action:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'assign'
                                            - 'block'
                                            - 'reserved'
                                    circuit-id:
                                        type: str
                                        description: no description
                                    circuit-id-type:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'hex'
                                            - 'string'
                                    description:
                                        type: str
                                        description: no description
                                    id:
                                        type: int
                                        description: no description
                                    ip:
                                        type: str
                                        description: no description
                                    mac:
                                        type: str
                                        description: no description
                                    remote-id:
                                        type: str
                                        description: no description
                                    remote-id-type:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'hex'
                                            - 'string'
                                    type:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'mac'
                                            - 'option82'
                            server-type:
                                type: str
                                description: no description
                                choices:
                                    - 'regular'
                                    - 'ipsec'
                            status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tftp-server:
                                description: no description
                                type: str
                            timezone:
                                type: str
                                description: no description
                                choices:
                                    - '00'
                                    - '01'
                                    - '02'
                                    - '03'
                                    - '04'
                                    - '05'
                                    - '06'
                                    - '07'
                                    - '08'
                                    - '09'
                                    - '10'
                                    - '11'
                                    - '12'
                                    - '13'
                                    - '14'
                                    - '15'
                                    - '16'
                                    - '17'
                                    - '18'
                                    - '19'
                                    - '20'
                                    - '21'
                                    - '22'
                                    - '23'
                                    - '24'
                                    - '25'
                                    - '26'
                                    - '27'
                                    - '28'
                                    - '29'
                                    - '30'
                                    - '31'
                                    - '32'
                                    - '33'
                                    - '34'
                                    - '35'
                                    - '36'
                                    - '37'
                                    - '38'
                                    - '39'
                                    - '40'
                                    - '41'
                                    - '42'
                                    - '43'
                                    - '44'
                                    - '45'
                                    - '46'
                                    - '47'
                                    - '48'
                                    - '49'
                                    - '50'
                                    - '51'
                                    - '52'
                                    - '53'
                                    - '54'
                                    - '55'
                                    - '56'
                                    - '57'
                                    - '58'
                                    - '59'
                                    - '60'
                                    - '61'
                                    - '62'
                                    - '63'
                                    - '64'
                                    - '65'
                                    - '66'
                                    - '67'
                                    - '68'
                                    - '69'
                                    - '70'
                                    - '71'
                                    - '72'
                                    - '73'
                                    - '74'
                                    - '75'
                                    - '76'
                                    - '77'
                                    - '78'
                                    - '79'
                                    - '80'
                                    - '81'
                                    - '82'
                                    - '83'
                                    - '84'
                                    - '85'
                                    - '86'
                                    - '87'
                            timezone-option:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'default'
                                    - 'specify'
                            vci-match:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vci-string:
                                description: no description
                                type: str
                            wifi-ac-service:
                                type: str
                                description: no description
                                choices:
                                    - 'specify'
                                    - 'local'
                            wifi-ac1:
                                type: str
                                description: no description
                            wifi-ac2:
                                type: str
                                description: no description
                            wifi-ac3:
                                type: str
                                description: no description
                            wins-server1:
                                type: str
                                description: no description
                            wins-server2:
                                type: str
                                description: no description
                    interface:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            dhcp-relay-agent-option:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp-relay-ip:
                                description: no description
                                type: str
                            dhcp-relay-service:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp-relay-type:
                                type: str
                                description: no description
                                choices:
                                    - 'regular'
                                    - 'ipsec'
                            ip:
                                type: str
                                description: no description
                            ipv6:
                                description: no description
                                type: dict
                                required: false
                                suboptions:
                                    autoconf:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-client-options:
                                        description: no description
                                        type: list
                                        choices:
                                         - rapid
                                         - iapd
                                         - iana
                                         - dns
                                         - dnsname
                                    dhcp6-information-request:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-prefix-delegation:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-prefix-hint:
                                        type: str
                                        description: no description
                                    dhcp6-prefix-hint-plt:
                                        type: int
                                        description: no description
                                    dhcp6-prefix-hint-vlt:
                                        type: int
                                        description: no description
                                    dhcp6-relay-ip:
                                        type: str
                                        description: no description
                                    dhcp6-relay-service:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-relay-type:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'regular'
                                    icmp6-send-redirect:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    interface-identifier:
                                        type: str
                                        description: no description
                                    ip6-address:
                                        type: str
                                        description: no description
                                    ip6-allowaccess:
                                        description: no description
                                        type: list
                                        choices:
                                         - https
                                         - ping
                                         - ssh
                                         - snmp
                                         - http
                                         - telnet
                                         - fgfm
                                         - capwap
                                         - fabric
                                    ip6-default-life:
                                        type: int
                                        description: no description
                                    ip6-delegated-prefix-list:
                                        description: no description
                                        type: list
                                        suboptions:
                                            autonomous-flag:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            onlink-flag:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            prefix-id:
                                                type: int
                                                description: no description
                                            rdnss:
                                                description: no description
                                                type: str
                                            rdnss-service:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'delegated'
                                                    - 'default'
                                                    - 'specify'
                                            subnet:
                                                type: str
                                                description: no description
                                            upstream-interface:
                                                type: str
                                                description: no description
                                            delegated-prefix-iaid:
                                                type: int
                                                description: no description
                                    ip6-dns-server-override:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-extra-addr:
                                        description: no description
                                        type: list
                                        suboptions:
                                            prefix:
                                                type: str
                                                description: no description
                                    ip6-hop-limit:
                                        type: int
                                        description: no description
                                    ip6-link-mtu:
                                        type: int
                                        description: no description
                                    ip6-manage-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-max-interval:
                                        type: int
                                        description: no description
                                    ip6-min-interval:
                                        type: int
                                        description: no description
                                    ip6-mode:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'static'
                                            - 'dhcp'
                                            - 'pppoe'
                                            - 'delegated'
                                    ip6-other-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-prefix-list:
                                        description: no description
                                        type: list
                                        suboptions:
                                            autonomous-flag:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            dnssl:
                                                description: no description
                                                type: str
                                            onlink-flag:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            preferred-life-time:
                                                type: int
                                                description: no description
                                            prefix:
                                                type: str
                                                description: no description
                                            rdnss:
                                                description: no description
                                                type: str
                                            valid-life-time:
                                                type: int
                                                description: no description
                                    ip6-reachable-time:
                                        type: int
                                        description: no description
                                    ip6-retrans-time:
                                        type: int
                                        description: no description
                                    ip6-send-adv:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-subnet:
                                        type: str
                                        description: no description
                                    ip6-upstream-interface:
                                        type: str
                                        description: no description
                                    nd-cert:
                                        type: str
                                        description: no description
                                    nd-cga-modifier:
                                        type: str
                                        description: no description
                                    nd-mode:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'basic'
                                            - 'SEND-compatible'
                                    nd-security-level:
                                        type: int
                                        description: no description
                                    nd-timestamp-delta:
                                        type: int
                                        description: no description
                                    nd-timestamp-fuzz:
                                        type: int
                                        description: no description
                                    unique-autoconf-addr:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrip6_link_local:
                                        type: str
                                        description: no description
                                    vrrp-virtual-mac6:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrrp6:
                                        description: no description
                                        type: list
                                        suboptions:
                                            accept-mode:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            adv-interval:
                                                type: int
                                                description: no description
                                            preempt:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            priority:
                                                type: int
                                                description: no description
                                            start-time:
                                                type: int
                                                description: no description
                                            status:
                                                type: str
                                                description: no description
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            vrdst6:
                                                type: str
                                                description: no description
                                            vrgrp:
                                                type: int
                                                description: no description
                                            vrid:
                                                type: int
                                                description: no description
                                            vrip6:
                                                type: str
                                                description: no description
                                    cli-conn6-status:
                                        type: int
                                        description: no description
                                    ip6-prefix-mode:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'dhcp6'
                                            - 'ra'
                                    ra-send-mtu:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-delegated-prefix-iaid:
                                        type: int
                                        description: no description
                            secondary-IP:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            secondaryip:
                                description: no description
                                type: list
                                suboptions:
                                    allowaccess:
                                        description: no description
                                        type: list
                                        choices:
                                         - https
                                         - ping
                                         - ssh
                                         - snmp
                                         - http
                                         - telnet
                                         - fgfm
                                         - auto-ipsec
                                         - radius-acct
                                         - probe-response
                                         - capwap
                                         - dnp
                                         - ftm
                                         - fabric
                                         - speed-test
                                    detectprotocol:
                                        description: no description
                                        type: list
                                        choices:
                                         - ping
                                         - tcp-echo
                                         - udp-echo
                                    detectserver:
                                        type: str
                                        description: no description
                                    gwdetect:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ha-priority:
                                        type: int
                                        description: no description
                                    id:
                                        type: int
                                        description: no description
                                    ip:
                                        type: str
                                        description: no description
                                    ping-serv-status:
                                        type: int
                                        description: no description
                                    seq:
                                        type: int
                                        description: no description
                            vlanid:
                                type: int
                                description: no description
                            dhcp-relay-interface-select-method:
                                type: str
                                description: no description
                                choices:
                                    - 'auto'
                                    - 'sdwan'
                                    - 'specify'
            name:
                type: str
                description: no description
            portal-message-override-group:
                type: str
                description: no description
            radius-server:
                type: str
                description: no description
            security:
                type: str
                description: no description
                choices:
                    - 'open'
                    - 'captive-portal'
                    - '8021x'
            selected-usergroups:
                type: str
                description: no description
            usergroup:
                type: str
                description: no description
            vdom:
                type: str
                description: no description
            vlanid:
                type: int
                description: no description
            dhcp-server:
                description: no description
                type: dict
                required: false
                suboptions:
                    auto-configuration:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    auto-managed-status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    conflicted-ip-timeout:
                        type: int
                        description: no description
                    ddns-auth:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'tsig'
                    ddns-key:
                        type: str
                        description: no description
                    ddns-keyname:
                        type: str
                        description: no description
                    ddns-server-ip:
                        type: str
                        description: no description
                    ddns-ttl:
                        type: int
                        description: no description
                    ddns-update:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-update-override:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-zone:
                        type: str
                        description: no description
                    default-gateway:
                        type: str
                        description: no description
                    dhcp-settings-from-fortiipam:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dns-server1:
                        type: str
                        description: no description
                    dns-server2:
                        type: str
                        description: no description
                    dns-server3:
                        type: str
                        description: no description
                    dns-server4:
                        type: str
                        description: no description
                    dns-service:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'specify'
                            - 'local'
                    domain:
                        type: str
                        description: no description
                    enable:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    exclude-range:
                        description: no description
                        type: list
                        suboptions:
                            end-ip:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                            start-ip:
                                type: str
                                description: no description
                    filename:
                        type: str
                        description: no description
                    forticlient-on-net-status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: no description
                    ip-mode:
                        type: str
                        description: no description
                        choices:
                            - 'range'
                            - 'usrgrp'
                    ip-range:
                        description: no description
                        type: list
                        suboptions:
                            end-ip:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                            start-ip:
                                type: str
                                description: no description
                    ipsec-lease-hold:
                        type: int
                        description: no description
                    lease-time:
                        type: int
                        description: no description
                    mac-acl-default-action:
                        type: str
                        description: no description
                        choices:
                            - 'assign'
                            - 'block'
                    netmask:
                        type: str
                        description: no description
                    next-server:
                        type: str
                        description: no description
                    ntp-server1:
                        type: str
                        description: no description
                    ntp-server2:
                        type: str
                        description: no description
                    ntp-server3:
                        type: str
                        description: no description
                    ntp-service:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'specify'
                            - 'local'
                    option1:
                        description: no description
                        type: str
                    option2:
                        description: no description
                        type: str
                    option3:
                        description: no description
                        type: str
                    option4:
                        type: str
                        description: no description
                    option5:
                        type: str
                        description: no description
                    option6:
                        type: str
                        description: no description
                    options:
                        description: no description
                        type: list
                        suboptions:
                            code:
                                type: int
                                description: no description
                            id:
                                type: int
                                description: no description
                            ip:
                                description: no description
                                type: str
                            type:
                                type: str
                                description: no description
                                choices:
                                    - 'hex'
                                    - 'string'
                                    - 'ip'
                                    - 'fqdn'
                            value:
                                type: str
                                description: no description
                    reserved-address:
                        description: no description
                        type: list
                        suboptions:
                            action:
                                type: str
                                description: no description
                                choices:
                                    - 'assign'
                                    - 'block'
                                    - 'reserved'
                            circuit-id:
                                type: str
                                description: no description
                            circuit-id-type:
                                type: str
                                description: no description
                                choices:
                                    - 'hex'
                                    - 'string'
                            description:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                            ip:
                                type: str
                                description: no description
                            mac:
                                type: str
                                description: no description
                            remote-id:
                                type: str
                                description: no description
                            remote-id-type:
                                type: str
                                description: no description
                                choices:
                                    - 'hex'
                                    - 'string'
                            type:
                                type: str
                                description: no description
                                choices:
                                    - 'mac'
                                    - 'option82'
                    server-type:
                        type: str
                        description: no description
                        choices:
                            - 'regular'
                            - 'ipsec'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    tftp-server:
                        description: no description
                        type: str
                    timezone:
                        type: str
                        description: no description
                        choices:
                            - '00'
                            - '01'
                            - '02'
                            - '03'
                            - '04'
                            - '05'
                            - '06'
                            - '07'
                            - '08'
                            - '09'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                            - '15'
                            - '16'
                            - '17'
                            - '18'
                            - '19'
                            - '20'
                            - '21'
                            - '22'
                            - '23'
                            - '24'
                            - '25'
                            - '26'
                            - '27'
                            - '28'
                            - '29'
                            - '30'
                            - '31'
                            - '32'
                            - '33'
                            - '34'
                            - '35'
                            - '36'
                            - '37'
                            - '38'
                            - '39'
                            - '40'
                            - '41'
                            - '42'
                            - '43'
                            - '44'
                            - '45'
                            - '46'
                            - '47'
                            - '48'
                            - '49'
                            - '50'
                            - '51'
                            - '52'
                            - '53'
                            - '54'
                            - '55'
                            - '56'
                            - '57'
                            - '58'
                            - '59'
                            - '60'
                            - '61'
                            - '62'
                            - '63'
                            - '64'
                            - '65'
                            - '66'
                            - '67'
                            - '68'
                            - '69'
                            - '70'
                            - '71'
                            - '72'
                            - '73'
                            - '74'
                            - '75'
                            - '76'
                            - '77'
                            - '78'
                            - '79'
                            - '80'
                            - '81'
                            - '82'
                            - '83'
                            - '84'
                            - '85'
                            - '86'
                            - '87'
                    timezone-option:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'default'
                            - 'specify'
                    vci-match:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    vci-string:
                        description: no description
                        type: str
                    wifi-ac-service:
                        type: str
                        description: no description
                        choices:
                            - 'specify'
                            - 'local'
                    wifi-ac1:
                        type: str
                        description: no description
                    wifi-ac2:
                        type: str
                        description: no description
                    wifi-ac3:
                        type: str
                        description: no description
                    wins-server1:
                        type: str
                        description: no description
                    wins-server2:
                        type: str
                        description: no description
            interface:
                description: no description
                type: dict
                required: false
                suboptions:
                    ac-name:
                        type: str
                        description: no description
                    aggregate:
                        type: str
                        description: no description
                    algorithm:
                        type: str
                        description: no description
                        choices:
                            - 'L2'
                            - 'L3'
                            - 'L4'
                            - 'LB'
                    alias:
                        type: str
                        description: no description
                    allowaccess:
                        description: no description
                        type: list
                        choices:
                         - https
                         - ping
                         - ssh
                         - snmp
                         - http
                         - telnet
                         - fgfm
                         - auto-ipsec
                         - radius-acct
                         - probe-response
                         - capwap
                         - dnp
                         - ftm
                         - fabric
                         - speed-test
                    ap-discover:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    arpforward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    atm-protocol:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'ipoa'
                    auth-type:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    auto-auth-extension-device:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth-measure-time:
                        type: int
                        description: no description
                    bfd:
                        type: str
                        description: no description
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    bfd-desired-min-tx:
                        type: int
                        description: no description
                    bfd-detect-mult:
                        type: int
                        description: no description
                    bfd-required-min-rx:
                        type: int
                        description: no description
                    broadcast-forticlient-discovery:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast-forward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    captive-portal:
                        type: int
                        description: no description
                    cli-conn-status:
                        type: int
                        description: no description
                    color:
                        type: int
                        description: no description
                    ddns:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-auth:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'tsig'
                    ddns-domain:
                        type: str
                        description: no description
                    ddns-key:
                        type: str
                        description: no description
                    ddns-keyname:
                        type: str
                        description: no description
                    ddns-password:
                        description: no description
                        type: str
                    ddns-server:
                        type: str
                        description: no description
                        choices:
                            - 'dhs.org'
                            - 'dyndns.org'
                            - 'dyns.net'
                            - 'tzo.com'
                            - 'ods.org'
                            - 'vavic.com'
                            - 'now.net.cn'
                            - 'dipdns.net'
                            - 'easydns.com'
                            - 'genericDDNS'
                    ddns-server-ip:
                        type: str
                        description: no description
                    ddns-sn:
                        type: str
                        description: no description
                    ddns-ttl:
                        type: int
                        description: no description
                    ddns-username:
                        type: str
                        description: no description
                    ddns-zone:
                        type: str
                        description: no description
                    dedicated-to:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'management'
                    defaultgw:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: no description
                    detected-peer-mtu:
                        type: int
                        description: no description
                    detectprotocol:
                        description: no description
                        type: list
                        choices:
                         - ping
                         - tcp-echo
                         - udp-echo
                    detectserver:
                        type: str
                        description: no description
                    device-access-list:
                        type: str
                        description: no description
                    device-identification:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    device-identification-active-scan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    device-netscan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    device-user-identification:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    devindex:
                        type: int
                        description: no description
                    dhcp-client-identifier:
                        type: str
                        description: no description
                    dhcp-relay-agent-option:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-interface:
                        type: str
                        description: no description
                    dhcp-relay-interface-select-method:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    dhcp-relay-ip:
                        description: no description
                        type: str
                    dhcp-relay-service:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-type:
                        type: str
                        description: no description
                        choices:
                            - 'regular'
                            - 'ipsec'
                    dhcp-renew-time:
                        type: int
                        description: no description
                    disc-retry-timeout:
                        type: int
                        description: no description
                    disconnect-threshold:
                        type: int
                        description: no description
                    distance:
                        type: int
                        description: no description
                    dns-query:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'recursive'
                            - 'non-recursive'
                    dns-server-override:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    drop-fragment:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    drop-overlapped-fragment:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    egress-cos:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    egress-shaping-profile:
                        type: str
                        description: no description
                    eip:
                        type: str
                        description: no description
                    endpoint-compliance:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    estimated-downstream-bandwidth:
                        type: int
                        description: no description
                    estimated-upstream-bandwidth:
                        type: int
                        description: no description
                    explicit-ftp-proxy:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    explicit-web-proxy:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    external:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fail-action-on-extender:
                        type: str
                        description: no description
                        choices:
                            - 'soft-restart'
                            - 'hard-restart'
                            - 'reboot'
                    fail-alert-interfaces:
                        type: str
                        description: no description
                    fail-alert-method:
                        type: str
                        description: no description
                        choices:
                            - 'link-failed-signal'
                            - 'link-down'
                    fail-detect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fail-detect-option:
                        description: no description
                        type: list
                        choices:
                         - detectserver
                         - link-down
                    fdp:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortiheartbeat:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink-backup-link:
                        type: int
                        description: no description
                    fortilink-neighbor-detect:
                        type: str
                        description: no description
                        choices:
                            - 'lldp'
                            - 'fortilink'
                    fortilink-split-interface:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink-stacking:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    forward-domain:
                        type: int
                        description: no description
                    forward-error-correction:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'rs-fec'
                            - 'base-r-fec'
                            - 'fec-cl91'
                            - 'fec-cl74'
                            - 'rs-544'
                            - 'none'
                            - 'cl91-rs-fec'
                            - 'cl74-fc-fec'
                    fp-anomaly:
                        description: no description
                        type: list
                        choices:
                         - drop_tcp_fin_noack
                         - pass_winnuke
                         - pass_tcpland
                         - pass_udpland
                         - pass_icmpland
                         - pass_ipland
                         - pass_iprr
                         - pass_ipssrr
                         - pass_iplsrr
                         - pass_ipstream
                         - pass_ipsecurity
                         - pass_iptimestamp
                         - pass_ipunknown_option
                         - pass_ipunknown_prot
                         - pass_icmp_frag
                         - pass_tcp_no_flag
                         - pass_tcp_fin_noack
                         - drop_winnuke
                         - drop_tcpland
                         - drop_udpland
                         - drop_icmpland
                         - drop_ipland
                         - drop_iprr
                         - drop_ipssrr
                         - drop_iplsrr
                         - drop_ipstream
                         - drop_ipsecurity
                         - drop_iptimestamp
                         - drop_ipunknown_option
                         - drop_ipunknown_prot
                         - drop_icmp_frag
                         - drop_tcp_no_flag
                    fp-disable:
                        description: no description
                        type: list
                        choices:
                         - all
                         - ipsec
                         - none
                    gateway-address:
                        type: str
                        description: no description
                    gi-gk:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    gwaddr:
                        type: str
                        description: no description
                    gwdetect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ha-priority:
                        type: int
                        description: no description
                    icmp-accept-redirect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp-redirect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp-send-redirect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ident-accept:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    idle-timeout:
                        type: int
                        description: no description
                    if-mdix:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'normal'
                            - 'crossover'
                    if-media:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'copper'
                            - 'fiber'
                    in-force-vlan-cos:
                        type: int
                        description: no description
                    inbandwidth:
                        type: int
                        description: no description
                    ingress-cos:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    ingress-shaping-profile:
                        type: str
                        description: no description
                    ingress-spillover-threshold:
                        type: int
                        description: no description
                    internal:
                        type: int
                        description: no description
                    ip:
                        type: str
                        description: no description
                    ip-managed-by-fortiipam:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ipmac:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ips-sniffer-mode:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ipunnumbered:
                        type: str
                        description: no description
                    ipv6:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            autoconf:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-client-options:
                                description: no description
                                type: list
                                choices:
                                 - rapid
                                 - iapd
                                 - iana
                                 - dns
                                 - dnsname
                            dhcp6-information-request:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-prefix-delegation:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-prefix-hint:
                                type: str
                                description: no description
                            dhcp6-prefix-hint-plt:
                                type: int
                                description: no description
                            dhcp6-prefix-hint-vlt:
                                type: int
                                description: no description
                            dhcp6-relay-ip:
                                type: str
                                description: no description
                            dhcp6-relay-service:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-relay-type:
                                type: str
                                description: no description
                                choices:
                                    - 'regular'
                            icmp6-send-redirect:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            interface-identifier:
                                type: str
                                description: no description
                            ip6-address:
                                type: str
                                description: no description
                            ip6-allowaccess:
                                description: no description
                                type: list
                                choices:
                                 - https
                                 - ping
                                 - ssh
                                 - snmp
                                 - http
                                 - telnet
                                 - fgfm
                                 - capwap
                                 - fabric
                            ip6-default-life:
                                type: int
                                description: no description
                            ip6-delegated-prefix-list:
                                description: no description
                                type: list
                                suboptions:
                                    autonomous-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    onlink-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    prefix-id:
                                        type: int
                                        description: no description
                                    rdnss:
                                        description: no description
                                        type: str
                                    rdnss-service:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'delegated'
                                            - 'default'
                                            - 'specify'
                                    subnet:
                                        type: str
                                        description: no description
                                    upstream-interface:
                                        type: str
                                        description: no description
                                    delegated-prefix-iaid:
                                        type: int
                                        description: no description
                            ip6-dns-server-override:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-extra-addr:
                                description: no description
                                type: list
                                suboptions:
                                    prefix:
                                        type: str
                                        description: no description
                            ip6-hop-limit:
                                type: int
                                description: no description
                            ip6-link-mtu:
                                type: int
                                description: no description
                            ip6-manage-flag:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-max-interval:
                                type: int
                                description: no description
                            ip6-min-interval:
                                type: int
                                description: no description
                            ip6-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'static'
                                    - 'dhcp'
                                    - 'pppoe'
                                    - 'delegated'
                            ip6-other-flag:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-prefix-list:
                                description: no description
                                type: list
                                suboptions:
                                    autonomous-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dnssl:
                                        description: no description
                                        type: str
                                    onlink-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    preferred-life-time:
                                        type: int
                                        description: no description
                                    prefix:
                                        type: str
                                        description: no description
                                    rdnss:
                                        description: no description
                                        type: str
                                    valid-life-time:
                                        type: int
                                        description: no description
                            ip6-reachable-time:
                                type: int
                                description: no description
                            ip6-retrans-time:
                                type: int
                                description: no description
                            ip6-send-adv:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-subnet:
                                type: str
                                description: no description
                            ip6-upstream-interface:
                                type: str
                                description: no description
                            nd-cert:
                                type: str
                                description: no description
                            nd-cga-modifier:
                                type: str
                                description: no description
                            nd-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'basic'
                                    - 'SEND-compatible'
                            nd-security-level:
                                type: int
                                description: no description
                            nd-timestamp-delta:
                                type: int
                                description: no description
                            nd-timestamp-fuzz:
                                type: int
                                description: no description
                            unique-autoconf-addr:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrip6_link_local:
                                type: str
                                description: no description
                            vrrp-virtual-mac6:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrrp6:
                                description: no description
                                type: list
                                suboptions:
                                    accept-mode:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    adv-interval:
                                        type: int
                                        description: no description
                                    preempt:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    priority:
                                        type: int
                                        description: no description
                                    start-time:
                                        type: int
                                        description: no description
                                    status:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrdst6:
                                        type: str
                                        description: no description
                                    vrgrp:
                                        type: int
                                        description: no description
                                    vrid:
                                        type: int
                                        description: no description
                                    vrip6:
                                        type: str
                                        description: no description
                            cli-conn6-status:
                                type: int
                                description: no description
                            ip6-prefix-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'dhcp6'
                                    - 'ra'
                            ra-send-mtu:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-delegated-prefix-iaid:
                                type: int
                                description: no description
                    l2forward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    l2tp-client:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-ha-slave:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-mode:
                        type: str
                        description: no description
                        choices:
                            - 'static'
                            - 'passive'
                            - 'active'
                    lacp-speed:
                        type: str
                        description: no description
                        choices:
                            - 'slow'
                            - 'fast'
                    lcp-echo-interval:
                        type: int
                        description: no description
                    lcp-max-echo-fails:
                        type: int
                        description: no description
                    link-up-delay:
                        type: int
                        description: no description
                    listen-forticlient-connection:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    lldp-network-policy:
                        type: str
                        description: no description
                    lldp-reception:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vdom'
                    lldp-transmission:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'disable'
                            - 'vdom'
                    log:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    macaddr:
                        type: str
                        description: no description
                    managed-subnetwork-size:
                        type: str
                        description: no description
                        choices:
                            - '256'
                            - '512'
                            - '1024'
                            - '2048'
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                            - '65536'
                            - '32'
                            - '64'
                            - '128'
                    management-ip:
                        type: str
                        description: no description
                    max-egress-burst-rate:
                        type: int
                        description: no description
                    max-egress-rate:
                        type: int
                        description: no description
                    measured-downstream-bandwidth:
                        type: int
                        description: no description
                    measured-upstream-bandwidth:
                        type: int
                        description: no description
                    mediatype:
                        type: str
                        description: no description
                        choices:
                            - 'serdes-sfp'
                            - 'sgmii-sfp'
                            - 'cfp2-sr10'
                            - 'cfp2-lr4'
                            - 'serdes-copper-sfp'
                            - 'sr'
                            - 'cr'
                            - 'lr'
                            - 'qsfp28-sr4'
                            - 'qsfp28-lr4'
                            - 'qsfp28-cr4'
                            - 'sr4'
                            - 'cr4'
                            - 'lr4'
                            - 'none'
                            - 'gmii'
                            - 'sgmii'
                    member:
                        type: str
                        description: no description
                    min-links:
                        type: int
                        description: no description
                    min-links-down:
                        type: str
                        description: no description
                        choices:
                            - 'operational'
                            - 'administrative'
                    mode:
                        type: str
                        description: no description
                        choices:
                            - 'static'
                            - 'dhcp'
                            - 'pppoe'
                            - 'pppoa'
                            - 'ipoa'
                            - 'eoa'
                    monitor-bandwidth:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    mtu:
                        type: int
                        description: no description
                    mtu-override:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    mux-type:
                        type: str
                        description: no description
                        choices:
                            - 'llc-encaps'
                            - 'vc-encaps'
                    name:
                        type: str
                        description: no description
                    ndiscforward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    netbios-forward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    netflow-sampler:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    np-qos-profile:
                        type: int
                        description: no description
                    npu-fastpath:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    nst:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    out-force-vlan-cos:
                        type: int
                        description: no description
                    outbandwidth:
                        type: int
                        description: no description
                    padt-retry-timeout:
                        type: int
                        description: no description
                    password:
                        description: no description
                        type: str
                    peer-interface:
                        type: str
                        description: no description
                    phy-mode:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'adsl'
                            - 'vdsl'
                            - 'adsl-auto'
                            - 'vdsl2'
                            - 'adsl2+'
                            - 'adsl2'
                            - 'g.dmt'
                            - 't1.413'
                            - 'g.lite'
                    ping-serv-status:
                        type: int
                        description: no description
                    poe:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    polling-interval:
                        type: int
                        description: no description
                    pppoe-unnumbered-negotiate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp-auth-type:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    pptp-client:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp-password:
                        description: no description
                        type: str
                    pptp-server-ip:
                        type: str
                        description: no description
                    pptp-timeout:
                        type: int
                        description: no description
                    pptp-user:
                        type: str
                        description: no description
                    preserve-session-route:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: no description
                    priority-override:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    proxy-captive-portal:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    redundant-interface:
                        type: str
                        description: no description
                    remote-ip:
                        type: str
                        description: no description
                    replacemsg-override-group:
                        type: str
                        description: no description
                    retransmission:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ring-rx:
                        type: int
                        description: no description
                    ring-tx:
                        type: int
                        description: no description
                    role:
                        type: str
                        description: no description
                        choices:
                            - 'lan'
                            - 'wan'
                            - 'dmz'
                            - 'undefined'
                    sample-direction:
                        type: str
                        description: no description
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sample-rate:
                        type: int
                        description: no description
                    scan-botnet-connections:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    secondary-IP:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    secondaryip:
                        description: no description
                        type: list
                        suboptions:
                            allowaccess:
                                description: no description
                                type: list
                                choices:
                                 - https
                                 - ping
                                 - ssh
                                 - snmp
                                 - http
                                 - telnet
                                 - fgfm
                                 - auto-ipsec
                                 - radius-acct
                                 - probe-response
                                 - capwap
                                 - dnp
                                 - ftm
                                 - fabric
                                 - speed-test
                            detectprotocol:
                                description: no description
                                type: list
                                choices:
                                 - ping
                                 - tcp-echo
                                 - udp-echo
                            detectserver:
                                type: str
                                description: no description
                            gwdetect:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ha-priority:
                                type: int
                                description: no description
                            id:
                                type: int
                                description: no description
                            ip:
                                type: str
                                description: no description
                            ping-serv-status:
                                type: int
                                description: no description
                            seq:
                                type: int
                                description: no description
                    security-8021x-dynamic-vlan-id:
                        type: int
                        description: no description
                    security-8021x-master:
                        type: str
                        description: no description
                    security-8021x-mode:
                        type: str
                        description: no description
                        choices:
                            - 'default'
                            - 'dynamic-vlan'
                            - 'fallback'
                            - 'slave'
                    security-exempt-list:
                        type: str
                        description: no description
                    security-external-logout:
                        type: str
                        description: no description
                    security-external-web:
                        type: str
                        description: no description
                    security-groups:
                        type: str
                        description: no description
                    security-mac-auth-bypass:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'mac-auth-only'
                    security-mode:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'captive-portal'
                            - '802.1X'
                    security-redirect-url:
                        type: str
                        description: no description
                    service-name:
                        type: str
                        description: no description
                    sflow-sampler:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    speed:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - '10full'
                            - '10half'
                            - '100full'
                            - '100half'
                            - '1000full'
                            - '1000half'
                            - '10000full'
                            - '1000auto'
                            - '10000auto'
                            - '40000full'
                            - '100Gfull'
                            - '25000full'
                            - '40000auto'
                            - '25000auto'
                            - '100Gauto'
                            - '400Gfull'
                            - '400Gauto'
                    spillover-threshold:
                        type: int
                        description: no description
                    src-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'down'
                            - 'up'
                    stp:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    stp-ha-slave:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    stpforward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    stpforward-mode:
                        type: str
                        description: no description
                        choices:
                            - 'rpl-all-ext-id'
                            - 'rpl-bridge-ext-id'
                            - 'rpl-nothing'
                    strip-priority-vlan-tag:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    subst:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    substitute-dst-mac:
                        type: str
                        description: no description
                    swc-first-create:
                        type: int
                        description: no description
                    swc-vlan:
                        type: int
                        description: no description
                    switch:
                        type: str
                        description: no description
                    switch-controller-access-vlan:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-arp-inspection:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-auth:
                        type: str
                        description: no description
                        choices:
                            - 'radius'
                            - 'usergroup'
                    switch-controller-dhcp-snooping:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-dhcp-snooping-option82:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-dhcp-snooping-verify-mac:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-feature:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'default-vlan'
                            - 'quarantine'
                            - 'sniffer'
                            - 'voice'
                            - 'camera'
                            - 'rspan'
                            - 'video'
                            - 'nac'
                            - 'nac-segment'
                    switch-controller-igmp-snooping:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-igmp-snooping-fast-leave:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-igmp-snooping-proxy:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-iot-scanning:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-learning-limit:
                        type: int
                        description: no description
                    switch-controller-mgmt-vlan:
                        type: int
                        description: no description
                    switch-controller-nac:
                        type: str
                        description: no description
                    switch-controller-radius-server:
                        type: str
                        description: no description
                    switch-controller-rspan-mode:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-source-ip:
                        type: str
                        description: no description
                        choices:
                            - 'outbound'
                            - 'fixed'
                    switch-controller-traffic-policy:
                        type: str
                        description: no description
                    tc-mode:
                        type: str
                        description: no description
                        choices:
                            - 'ptm'
                            - 'atm'
                    tcp-mss:
                        type: int
                        description: no description
                    trunk:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    trust-ip-1:
                        type: str
                        description: no description
                    trust-ip-2:
                        type: str
                        description: no description
                    trust-ip-3:
                        type: str
                        description: no description
                    trust-ip6-1:
                        type: str
                        description: no description
                    trust-ip6-2:
                        type: str
                        description: no description
                    trust-ip6-3:
                        type: str
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'physical'
                            - 'vlan'
                            - 'aggregate'
                            - 'redundant'
                            - 'tunnel'
                            - 'wireless'
                            - 'vdom-link'
                            - 'loopback'
                            - 'switch'
                            - 'hard-switch'
                            - 'hdlc'
                            - 'vap-switch'
                            - 'wl-mesh'
                            - 'fortilink'
                            - 'switch-vlan'
                            - 'fctrl-trunk'
                            - 'tdm'
                            - 'fext-wan'
                            - 'vxlan'
                            - 'emac-vlan'
                            - 'geneve'
                            - 'ssl'
                            - 'lan-extension'
                    username:
                        type: str
                        description: no description
                    vci:
                        type: int
                        description: no description
                    vectoring:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    vindex:
                        type: int
                        description: no description
                    vlan-protocol:
                        type: str
                        description: no description
                        choices:
                            - '8021q'
                            - '8021ad'
                    vlanforward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    vlanid:
                        type: int
                        description: no description
                    vpi:
                        type: int
                        description: no description
                    vrf:
                        type: int
                        description: no description
                    vrrp:
                        description: no description
                        type: list
                        suboptions:
                            accept-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            adv-interval:
                                type: int
                                description: no description
                            ignore-default-route:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preempt:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            priority:
                                type: int
                                description: no description
                            start-time:
                                type: int
                                description: no description
                            status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: no description
                                choices:
                                    - '2'
                                    - '3'
                            vrdst:
                                description: no description
                                type: str
                            vrdst-priority:
                                type: int
                                description: no description
                            vrgrp:
                                type: int
                                description: no description
                            vrid:
                                type: int
                                description: no description
                            vrip:
                                type: str
                                description: no description
                    vrrp-virtual-mac:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    wccp:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    weight:
                        type: int
                        description: no description
                    wifi-5g-threshold:
                        type: str
                        description: no description
                    wifi-acl:
                        type: str
                        description: no description
                        choices:
                            - 'deny'
                            - 'allow'
                    wifi-ap-band:
                        type: str
                        description: no description
                        choices:
                            - 'any'
                            - '5g-preferred'
                            - '5g-only'
                    wifi-auth:
                        type: str
                        description: no description
                        choices:
                            - 'PSK'
                            - 'RADIUS'
                            - 'radius'
                            - 'usergroup'
                    wifi-auto-connect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-auto-save:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-broadcast-ssid:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-encrypt:
                        type: str
                        description: no description
                        choices:
                            - 'TKIP'
                            - 'AES'
                    wifi-fragment-threshold:
                        type: int
                        description: no description
                    wifi-key:
                        description: no description
                        type: str
                    wifi-keyindex:
                        type: int
                        description: no description
                    wifi-mac-filter:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-passphrase:
                        description: no description
                        type: str
                    wifi-radius-server:
                        type: str
                        description: no description
                    wifi-rts-threshold:
                        type: int
                        description: no description
                    wifi-security:
                        type: str
                        description: no description
                        choices:
                            - 'None'
                            - 'WEP64'
                            - 'wep64'
                            - 'WEP128'
                            - 'wep128'
                            - 'WPA_PSK'
                            - 'WPA_RADIUS'
                            - 'WPA'
                            - 'WPA2'
                            - 'WPA2_AUTO'
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa-only-personal'
                            - 'wpa-only-enterprise'
                            - 'wpa2-only-personal'
                            - 'wpa2-only-enterprise'
                    wifi-ssid:
                        type: str
                        description: no description
                    wifi-usergroup:
                        type: str
                        description: no description
                    wins-ip:
                        type: str
                        description: no description
                    dhcp-relay-request-all-server:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    stp-ha-secondary:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    switch-controller-dynamic:
                        type: str
                        description: no description
                    auth-cert:
                        type: str
                        description: no description
                    auth-portal-addr:
                        type: str
                        description: no description
                    dhcp-classless-route-addition:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-link-selection:
                        type: str
                        description: no description
                    dns-server-protocol:
                        description: description
                        type: list
                        choices:
                         - cleartext
                         - dot
                         - doh
                    eap-ca-cert:
                        type: str
                        description: no description
                    eap-identity:
                        type: str
                        description: no description
                    eap-method:
                        type: str
                        description: no description
                        choices:
                            - 'tls'
                            - 'peap'
                    eap-password:
                        description: description
                        type: str
                    eap-supplicant:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    eap-user-cert:
                        type: str
                        description: no description
                    ike-saml-server:
                        type: str
                        description: no description
                    lacp-ha-secondary:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pvc-atm-qos:
                        type: str
                        description: no description
                        choices:
                            - 'cbr'
                            - 'rt-vbr'
                            - 'nrt-vbr'
                    pvc-chan:
                        type: int
                        description: no description
                    pvc-crc:
                        type: int
                        description: no description
                    pvc-pcr:
                        type: int
                        description: no description
                    pvc-scr:
                        type: int
                        description: no description
                    pvc-vlan-id:
                        type: int
                        description: no description
                    pvc-vlan-rx-id:
                        type: int
                        description: no description
                    pvc-vlan-rx-op:
                        type: str
                        description: no description
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    pvc-vlan-tx-id:
                        type: int
                        description: no description
                    pvc-vlan-tx-op:
                        type: str
                        description: no description
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    reachable-time:
                        type: int
                        description: no description
                    select-profile-30a-35b:
                        type: str
                        description: no description
                        choices:
                            - '30A'
                            - '35B'
                    sfp-dsl:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-adsl-fallback:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-autodetect:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-mac:
                        type: str
                        description: no description
                    sw-algorithm:
                        type: str
                        description: no description
                        choices:
                            - 'l2'
                            - 'l3'
                            - 'eh'
                    system-id:
                        type: str
                        description: no description
                    system-id-type:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'user'
                    vlan-id:
                        type: int
                        description: no description
                    vlan-op-mode:
                        type: str
                        description: no description
                        choices:
                            - 'tag'
                            - 'untag'
                            - 'passthrough'

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
      fmgr_fsp_vlan:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         fsp_vlan:
            _dhcp-status: <value in [disable, enable]>
            auth: <value in [radius, usergroup]>
            color: <value of integer>
            comments: <value of string>
            dynamic_mapping:
              -
                  _dhcp-status: <value in [disable, enable]>
                  _scope:
                    -
                        name: <value of string>
                        vdom: <value of string>
                  dhcp-server:
                     auto-configuration: <value in [disable, enable]>
                     auto-managed-status: <value in [disable, enable]>
                     conflicted-ip-timeout: <value of integer>
                     ddns-auth: <value in [disable, tsig]>
                     ddns-key: <value of string>
                     ddns-keyname: <value of string>
                     ddns-server-ip: <value of string>
                     ddns-ttl: <value of integer>
                     ddns-update: <value in [disable, enable]>
                     ddns-update-override: <value in [disable, enable]>
                     ddns-zone: <value of string>
                     default-gateway: <value of string>
                     dhcp-settings-from-fortiipam: <value in [disable, enable]>
                     dns-server1: <value of string>
                     dns-server2: <value of string>
                     dns-server3: <value of string>
                     dns-server4: <value of string>
                     dns-service: <value in [default, specify, local]>
                     domain: <value of string>
                     enable: <value in [disable, enable]>
                     exclude-range:
                       -
                           end-ip: <value of string>
                           id: <value of integer>
                           start-ip: <value of string>
                     filename: <value of string>
                     forticlient-on-net-status: <value in [disable, enable]>
                     id: <value of integer>
                     ip-mode: <value in [range, usrgrp]>
                     ip-range:
                       -
                           end-ip: <value of string>
                           id: <value of integer>
                           start-ip: <value of string>
                     ipsec-lease-hold: <value of integer>
                     lease-time: <value of integer>
                     mac-acl-default-action: <value in [assign, block]>
                     netmask: <value of string>
                     next-server: <value of string>
                     ntp-server1: <value of string>
                     ntp-server2: <value of string>
                     ntp-server3: <value of string>
                     ntp-service: <value in [default, specify, local]>
                     option1: <value of string>
                     option2: <value of string>
                     option3: <value of string>
                     option4: <value of string>
                     option5: <value of string>
                     option6: <value of string>
                     options:
                       -
                           code: <value of integer>
                           id: <value of integer>
                           ip: <value of string>
                           type: <value in [hex, string, ip, ...]>
                           value: <value of string>
                     reserved-address:
                       -
                           action: <value in [assign, block, reserved]>
                           circuit-id: <value of string>
                           circuit-id-type: <value in [hex, string]>
                           description: <value of string>
                           id: <value of integer>
                           ip: <value of string>
                           mac: <value of string>
                           remote-id: <value of string>
                           remote-id-type: <value in [hex, string]>
                           type: <value in [mac, option82]>
                     server-type: <value in [regular, ipsec]>
                     status: <value in [disable, enable]>
                     tftp-server: <value of string>
                     timezone: <value in [00, 01, 02, ...]>
                     timezone-option: <value in [disable, default, specify]>
                     vci-match: <value in [disable, enable]>
                     vci-string: <value of string>
                     wifi-ac-service: <value in [specify, local]>
                     wifi-ac1: <value of string>
                     wifi-ac2: <value of string>
                     wifi-ac3: <value of string>
                     wins-server1: <value of string>
                     wins-server2: <value of string>
                  interface:
                     dhcp-relay-agent-option: <value in [disable, enable]>
                     dhcp-relay-ip: <value of string>
                     dhcp-relay-service: <value in [disable, enable]>
                     dhcp-relay-type: <value in [regular, ipsec]>
                     ip: <value of string>
                     ipv6:
                        autoconf: <value in [disable, enable]>
                        dhcp6-client-options:
                          - rapid
                          - iapd
                          - iana
                          - dns
                          - dnsname
                        dhcp6-information-request: <value in [disable, enable]>
                        dhcp6-prefix-delegation: <value in [disable, enable]>
                        dhcp6-prefix-hint: <value of string>
                        dhcp6-prefix-hint-plt: <value of integer>
                        dhcp6-prefix-hint-vlt: <value of integer>
                        dhcp6-relay-ip: <value of string>
                        dhcp6-relay-service: <value in [disable, enable]>
                        dhcp6-relay-type: <value in [regular]>
                        icmp6-send-redirect: <value in [disable, enable]>
                        interface-identifier: <value of string>
                        ip6-address: <value of string>
                        ip6-allowaccess:
                          - https
                          - ping
                          - ssh
                          - snmp
                          - http
                          - telnet
                          - fgfm
                          - capwap
                          - fabric
                        ip6-default-life: <value of integer>
                        ip6-delegated-prefix-list:
                          -
                              autonomous-flag: <value in [disable, enable]>
                              onlink-flag: <value in [disable, enable]>
                              prefix-id: <value of integer>
                              rdnss: <value of string>
                              rdnss-service: <value in [delegated, default, specify]>
                              subnet: <value of string>
                              upstream-interface: <value of string>
                              delegated-prefix-iaid: <value of integer>
                        ip6-dns-server-override: <value in [disable, enable]>
                        ip6-extra-addr:
                          -
                              prefix: <value of string>
                        ip6-hop-limit: <value of integer>
                        ip6-link-mtu: <value of integer>
                        ip6-manage-flag: <value in [disable, enable]>
                        ip6-max-interval: <value of integer>
                        ip6-min-interval: <value of integer>
                        ip6-mode: <value in [static, dhcp, pppoe, ...]>
                        ip6-other-flag: <value in [disable, enable]>
                        ip6-prefix-list:
                          -
                              autonomous-flag: <value in [disable, enable]>
                              dnssl: <value of string>
                              onlink-flag: <value in [disable, enable]>
                              preferred-life-time: <value of integer>
                              prefix: <value of string>
                              rdnss: <value of string>
                              valid-life-time: <value of integer>
                        ip6-reachable-time: <value of integer>
                        ip6-retrans-time: <value of integer>
                        ip6-send-adv: <value in [disable, enable]>
                        ip6-subnet: <value of string>
                        ip6-upstream-interface: <value of string>
                        nd-cert: <value of string>
                        nd-cga-modifier: <value of string>
                        nd-mode: <value in [basic, SEND-compatible]>
                        nd-security-level: <value of integer>
                        nd-timestamp-delta: <value of integer>
                        nd-timestamp-fuzz: <value of integer>
                        unique-autoconf-addr: <value in [disable, enable]>
                        vrip6_link_local: <value of string>
                        vrrp-virtual-mac6: <value in [disable, enable]>
                        vrrp6:
                          -
                              accept-mode: <value in [disable, enable]>
                              adv-interval: <value of integer>
                              preempt: <value in [disable, enable]>
                              priority: <value of integer>
                              start-time: <value of integer>
                              status: <value in [disable, enable]>
                              vrdst6: <value of string>
                              vrgrp: <value of integer>
                              vrid: <value of integer>
                              vrip6: <value of string>
                        cli-conn6-status: <value of integer>
                        ip6-prefix-mode: <value in [dhcp6, ra]>
                        ra-send-mtu: <value in [disable, enable]>
                        ip6-delegated-prefix-iaid: <value of integer>
                     secondary-IP: <value in [disable, enable]>
                     secondaryip:
                       -
                           allowaccess:
                             - https
                             - ping
                             - ssh
                             - snmp
                             - http
                             - telnet
                             - fgfm
                             - auto-ipsec
                             - radius-acct
                             - probe-response
                             - capwap
                             - dnp
                             - ftm
                             - fabric
                             - speed-test
                           detectprotocol:
                             - ping
                             - tcp-echo
                             - udp-echo
                           detectserver: <value of string>
                           gwdetect: <value in [disable, enable]>
                           ha-priority: <value of integer>
                           id: <value of integer>
                           ip: <value of string>
                           ping-serv-status: <value of integer>
                           seq: <value of integer>
                     vlanid: <value of integer>
                     dhcp-relay-interface-select-method: <value in [auto, sdwan, specify]>
            name: <value of string>
            portal-message-override-group: <value of string>
            radius-server: <value of string>
            security: <value in [open, captive-portal, 8021x]>
            selected-usergroups: <value of string>
            usergroup: <value of string>
            vdom: <value of string>
            vlanid: <value of integer>
            dhcp-server:
               auto-configuration: <value in [disable, enable]>
               auto-managed-status: <value in [disable, enable]>
               conflicted-ip-timeout: <value of integer>
               ddns-auth: <value in [disable, tsig]>
               ddns-key: <value of string>
               ddns-keyname: <value of string>
               ddns-server-ip: <value of string>
               ddns-ttl: <value of integer>
               ddns-update: <value in [disable, enable]>
               ddns-update-override: <value in [disable, enable]>
               ddns-zone: <value of string>
               default-gateway: <value of string>
               dhcp-settings-from-fortiipam: <value in [disable, enable]>
               dns-server1: <value of string>
               dns-server2: <value of string>
               dns-server3: <value of string>
               dns-server4: <value of string>
               dns-service: <value in [default, specify, local]>
               domain: <value of string>
               enable: <value in [disable, enable]>
               exclude-range:
                 -
                     end-ip: <value of string>
                     id: <value of integer>
                     start-ip: <value of string>
               filename: <value of string>
               forticlient-on-net-status: <value in [disable, enable]>
               id: <value of integer>
               ip-mode: <value in [range, usrgrp]>
               ip-range:
                 -
                     end-ip: <value of string>
                     id: <value of integer>
                     start-ip: <value of string>
               ipsec-lease-hold: <value of integer>
               lease-time: <value of integer>
               mac-acl-default-action: <value in [assign, block]>
               netmask: <value of string>
               next-server: <value of string>
               ntp-server1: <value of string>
               ntp-server2: <value of string>
               ntp-server3: <value of string>
               ntp-service: <value in [default, specify, local]>
               option1: <value of string>
               option2: <value of string>
               option3: <value of string>
               option4: <value of string>
               option5: <value of string>
               option6: <value of string>
               options:
                 -
                     code: <value of integer>
                     id: <value of integer>
                     ip: <value of string>
                     type: <value in [hex, string, ip, ...]>
                     value: <value of string>
               reserved-address:
                 -
                     action: <value in [assign, block, reserved]>
                     circuit-id: <value of string>
                     circuit-id-type: <value in [hex, string]>
                     description: <value of string>
                     id: <value of integer>
                     ip: <value of string>
                     mac: <value of string>
                     remote-id: <value of string>
                     remote-id-type: <value in [hex, string]>
                     type: <value in [mac, option82]>
               server-type: <value in [regular, ipsec]>
               status: <value in [disable, enable]>
               tftp-server: <value of string>
               timezone: <value in [00, 01, 02, ...]>
               timezone-option: <value in [disable, default, specify]>
               vci-match: <value in [disable, enable]>
               vci-string: <value of string>
               wifi-ac-service: <value in [specify, local]>
               wifi-ac1: <value of string>
               wifi-ac2: <value of string>
               wifi-ac3: <value of string>
               wins-server1: <value of string>
               wins-server2: <value of string>
            interface:
               ac-name: <value of string>
               aggregate: <value of string>
               algorithm: <value in [L2, L3, L4, ...]>
               alias: <value of string>
               allowaccess:
                 - https
                 - ping
                 - ssh
                 - snmp
                 - http
                 - telnet
                 - fgfm
                 - auto-ipsec
                 - radius-acct
                 - probe-response
                 - capwap
                 - dnp
                 - ftm
                 - fabric
                 - speed-test
               ap-discover: <value in [disable, enable]>
               arpforward: <value in [disable, enable]>
               atm-protocol: <value in [none, ipoa]>
               auth-type: <value in [auto, pap, chap, ...]>
               auto-auth-extension-device: <value in [disable, enable]>
               bandwidth-measure-time: <value of integer>
               bfd: <value in [global, enable, disable]>
               bfd-desired-min-tx: <value of integer>
               bfd-detect-mult: <value of integer>
               bfd-required-min-rx: <value of integer>
               broadcast-forticlient-discovery: <value in [disable, enable]>
               broadcast-forward: <value in [disable, enable]>
               captive-portal: <value of integer>
               cli-conn-status: <value of integer>
               color: <value of integer>
               ddns: <value in [disable, enable]>
               ddns-auth: <value in [disable, tsig]>
               ddns-domain: <value of string>
               ddns-key: <value of string>
               ddns-keyname: <value of string>
               ddns-password: <value of string>
               ddns-server: <value in [dhs.org, dyndns.org, dyns.net, ...]>
               ddns-server-ip: <value of string>
               ddns-sn: <value of string>
               ddns-ttl: <value of integer>
               ddns-username: <value of string>
               ddns-zone: <value of string>
               dedicated-to: <value in [none, management]>
               defaultgw: <value in [disable, enable]>
               description: <value of string>
               detected-peer-mtu: <value of integer>
               detectprotocol:
                 - ping
                 - tcp-echo
                 - udp-echo
               detectserver: <value of string>
               device-access-list: <value of string>
               device-identification: <value in [disable, enable]>
               device-identification-active-scan: <value in [disable, enable]>
               device-netscan: <value in [disable, enable]>
               device-user-identification: <value in [disable, enable]>
               devindex: <value of integer>
               dhcp-client-identifier: <value of string>
               dhcp-relay-agent-option: <value in [disable, enable]>
               dhcp-relay-interface: <value of string>
               dhcp-relay-interface-select-method: <value in [auto, sdwan, specify]>
               dhcp-relay-ip: <value of string>
               dhcp-relay-service: <value in [disable, enable]>
               dhcp-relay-type: <value in [regular, ipsec]>
               dhcp-renew-time: <value of integer>
               disc-retry-timeout: <value of integer>
               disconnect-threshold: <value of integer>
               distance: <value of integer>
               dns-query: <value in [disable, recursive, non-recursive]>
               dns-server-override: <value in [disable, enable]>
               drop-fragment: <value in [disable, enable]>
               drop-overlapped-fragment: <value in [disable, enable]>
               egress-cos: <value in [disable, cos0, cos1, ...]>
               egress-shaping-profile: <value of string>
               eip: <value of string>
               endpoint-compliance: <value in [disable, enable]>
               estimated-downstream-bandwidth: <value of integer>
               estimated-upstream-bandwidth: <value of integer>
               explicit-ftp-proxy: <value in [disable, enable]>
               explicit-web-proxy: <value in [disable, enable]>
               external: <value in [disable, enable]>
               fail-action-on-extender: <value in [soft-restart, hard-restart, reboot]>
               fail-alert-interfaces: <value of string>
               fail-alert-method: <value in [link-failed-signal, link-down]>
               fail-detect: <value in [disable, enable]>
               fail-detect-option:
                 - detectserver
                 - link-down
               fdp: <value in [disable, enable]>
               fortiheartbeat: <value in [disable, enable]>
               fortilink: <value in [disable, enable]>
               fortilink-backup-link: <value of integer>
               fortilink-neighbor-detect: <value in [lldp, fortilink]>
               fortilink-split-interface: <value in [disable, enable]>
               fortilink-stacking: <value in [disable, enable]>
               forward-domain: <value of integer>
               forward-error-correction: <value in [disable, enable, rs-fec, ...]>
               fp-anomaly:
                 - drop_tcp_fin_noack
                 - pass_winnuke
                 - pass_tcpland
                 - pass_udpland
                 - pass_icmpland
                 - pass_ipland
                 - pass_iprr
                 - pass_ipssrr
                 - pass_iplsrr
                 - pass_ipstream
                 - pass_ipsecurity
                 - pass_iptimestamp
                 - pass_ipunknown_option
                 - pass_ipunknown_prot
                 - pass_icmp_frag
                 - pass_tcp_no_flag
                 - pass_tcp_fin_noack
                 - drop_winnuke
                 - drop_tcpland
                 - drop_udpland
                 - drop_icmpland
                 - drop_ipland
                 - drop_iprr
                 - drop_ipssrr
                 - drop_iplsrr
                 - drop_ipstream
                 - drop_ipsecurity
                 - drop_iptimestamp
                 - drop_ipunknown_option
                 - drop_ipunknown_prot
                 - drop_icmp_frag
                 - drop_tcp_no_flag
               fp-disable:
                 - all
                 - ipsec
                 - none
               gateway-address: <value of string>
               gi-gk: <value in [disable, enable]>
               gwaddr: <value of string>
               gwdetect: <value in [disable, enable]>
               ha-priority: <value of integer>
               icmp-accept-redirect: <value in [disable, enable]>
               icmp-redirect: <value in [disable, enable]>
               icmp-send-redirect: <value in [disable, enable]>
               ident-accept: <value in [disable, enable]>
               idle-timeout: <value of integer>
               if-mdix: <value in [auto, normal, crossover]>
               if-media: <value in [auto, copper, fiber]>
               in-force-vlan-cos: <value of integer>
               inbandwidth: <value of integer>
               ingress-cos: <value in [disable, cos0, cos1, ...]>
               ingress-shaping-profile: <value of string>
               ingress-spillover-threshold: <value of integer>
               internal: <value of integer>
               ip: <value of string>
               ip-managed-by-fortiipam: <value in [disable, enable]>
               ipmac: <value in [disable, enable]>
               ips-sniffer-mode: <value in [disable, enable]>
               ipunnumbered: <value of string>
               ipv6:
                  autoconf: <value in [disable, enable]>
                  dhcp6-client-options:
                    - rapid
                    - iapd
                    - iana
                    - dns
                    - dnsname
                  dhcp6-information-request: <value in [disable, enable]>
                  dhcp6-prefix-delegation: <value in [disable, enable]>
                  dhcp6-prefix-hint: <value of string>
                  dhcp6-prefix-hint-plt: <value of integer>
                  dhcp6-prefix-hint-vlt: <value of integer>
                  dhcp6-relay-ip: <value of string>
                  dhcp6-relay-service: <value in [disable, enable]>
                  dhcp6-relay-type: <value in [regular]>
                  icmp6-send-redirect: <value in [disable, enable]>
                  interface-identifier: <value of string>
                  ip6-address: <value of string>
                  ip6-allowaccess:
                    - https
                    - ping
                    - ssh
                    - snmp
                    - http
                    - telnet
                    - fgfm
                    - capwap
                    - fabric
                  ip6-default-life: <value of integer>
                  ip6-delegated-prefix-list:
                    -
                        autonomous-flag: <value in [disable, enable]>
                        onlink-flag: <value in [disable, enable]>
                        prefix-id: <value of integer>
                        rdnss: <value of string>
                        rdnss-service: <value in [delegated, default, specify]>
                        subnet: <value of string>
                        upstream-interface: <value of string>
                        delegated-prefix-iaid: <value of integer>
                  ip6-dns-server-override: <value in [disable, enable]>
                  ip6-extra-addr:
                    -
                        prefix: <value of string>
                  ip6-hop-limit: <value of integer>
                  ip6-link-mtu: <value of integer>
                  ip6-manage-flag: <value in [disable, enable]>
                  ip6-max-interval: <value of integer>
                  ip6-min-interval: <value of integer>
                  ip6-mode: <value in [static, dhcp, pppoe, ...]>
                  ip6-other-flag: <value in [disable, enable]>
                  ip6-prefix-list:
                    -
                        autonomous-flag: <value in [disable, enable]>
                        dnssl: <value of string>
                        onlink-flag: <value in [disable, enable]>
                        preferred-life-time: <value of integer>
                        prefix: <value of string>
                        rdnss: <value of string>
                        valid-life-time: <value of integer>
                  ip6-reachable-time: <value of integer>
                  ip6-retrans-time: <value of integer>
                  ip6-send-adv: <value in [disable, enable]>
                  ip6-subnet: <value of string>
                  ip6-upstream-interface: <value of string>
                  nd-cert: <value of string>
                  nd-cga-modifier: <value of string>
                  nd-mode: <value in [basic, SEND-compatible]>
                  nd-security-level: <value of integer>
                  nd-timestamp-delta: <value of integer>
                  nd-timestamp-fuzz: <value of integer>
                  unique-autoconf-addr: <value in [disable, enable]>
                  vrip6_link_local: <value of string>
                  vrrp-virtual-mac6: <value in [disable, enable]>
                  vrrp6:
                    -
                        accept-mode: <value in [disable, enable]>
                        adv-interval: <value of integer>
                        preempt: <value in [disable, enable]>
                        priority: <value of integer>
                        start-time: <value of integer>
                        status: <value in [disable, enable]>
                        vrdst6: <value of string>
                        vrgrp: <value of integer>
                        vrid: <value of integer>
                        vrip6: <value of string>
                  cli-conn6-status: <value of integer>
                  ip6-prefix-mode: <value in [dhcp6, ra]>
                  ra-send-mtu: <value in [disable, enable]>
                  ip6-delegated-prefix-iaid: <value of integer>
               l2forward: <value in [disable, enable]>
               l2tp-client: <value in [disable, enable]>
               lacp-ha-slave: <value in [disable, enable]>
               lacp-mode: <value in [static, passive, active]>
               lacp-speed: <value in [slow, fast]>
               lcp-echo-interval: <value of integer>
               lcp-max-echo-fails: <value of integer>
               link-up-delay: <value of integer>
               listen-forticlient-connection: <value in [disable, enable]>
               lldp-network-policy: <value of string>
               lldp-reception: <value in [disable, enable, vdom]>
               lldp-transmission: <value in [enable, disable, vdom]>
               log: <value in [disable, enable]>
               macaddr: <value of string>
               managed-subnetwork-size: <value in [256, 512, 1024, ...]>
               management-ip: <value of string>
               max-egress-burst-rate: <value of integer>
               max-egress-rate: <value of integer>
               measured-downstream-bandwidth: <value of integer>
               measured-upstream-bandwidth: <value of integer>
               mediatype: <value in [serdes-sfp, sgmii-sfp, cfp2-sr10, ...]>
               member: <value of string>
               min-links: <value of integer>
               min-links-down: <value in [operational, administrative]>
               mode: <value in [static, dhcp, pppoe, ...]>
               monitor-bandwidth: <value in [disable, enable]>
               mtu: <value of integer>
               mtu-override: <value in [disable, enable]>
               mux-type: <value in [llc-encaps, vc-encaps]>
               name: <value of string>
               ndiscforward: <value in [disable, enable]>
               netbios-forward: <value in [disable, enable]>
               netflow-sampler: <value in [disable, tx, rx, ...]>
               np-qos-profile: <value of integer>
               npu-fastpath: <value in [disable, enable]>
               nst: <value in [disable, enable]>
               out-force-vlan-cos: <value of integer>
               outbandwidth: <value of integer>
               padt-retry-timeout: <value of integer>
               password: <value of string>
               peer-interface: <value of string>
               phy-mode: <value in [auto, adsl, vdsl, ...]>
               ping-serv-status: <value of integer>
               poe: <value in [disable, enable]>
               polling-interval: <value of integer>
               pppoe-unnumbered-negotiate: <value in [disable, enable]>
               pptp-auth-type: <value in [auto, pap, chap, ...]>
               pptp-client: <value in [disable, enable]>
               pptp-password: <value of string>
               pptp-server-ip: <value of string>
               pptp-timeout: <value of integer>
               pptp-user: <value of string>
               preserve-session-route: <value in [disable, enable]>
               priority: <value of integer>
               priority-override: <value in [disable, enable]>
               proxy-captive-portal: <value in [disable, enable]>
               redundant-interface: <value of string>
               remote-ip: <value of string>
               replacemsg-override-group: <value of string>
               retransmission: <value in [disable, enable]>
               ring-rx: <value of integer>
               ring-tx: <value of integer>
               role: <value in [lan, wan, dmz, ...]>
               sample-direction: <value in [rx, tx, both]>
               sample-rate: <value of integer>
               scan-botnet-connections: <value in [disable, block, monitor]>
               secondary-IP: <value in [disable, enable]>
               secondaryip:
                 -
                     allowaccess:
                       - https
                       - ping
                       - ssh
                       - snmp
                       - http
                       - telnet
                       - fgfm
                       - auto-ipsec
                       - radius-acct
                       - probe-response
                       - capwap
                       - dnp
                       - ftm
                       - fabric
                       - speed-test
                     detectprotocol:
                       - ping
                       - tcp-echo
                       - udp-echo
                     detectserver: <value of string>
                     gwdetect: <value in [disable, enable]>
                     ha-priority: <value of integer>
                     id: <value of integer>
                     ip: <value of string>
                     ping-serv-status: <value of integer>
                     seq: <value of integer>
               security-8021x-dynamic-vlan-id: <value of integer>
               security-8021x-master: <value of string>
               security-8021x-mode: <value in [default, dynamic-vlan, fallback, ...]>
               security-exempt-list: <value of string>
               security-external-logout: <value of string>
               security-external-web: <value of string>
               security-groups: <value of string>
               security-mac-auth-bypass: <value in [disable, enable, mac-auth-only]>
               security-mode: <value in [none, captive-portal, 802.1X]>
               security-redirect-url: <value of string>
               service-name: <value of string>
               sflow-sampler: <value in [disable, enable]>
               speed: <value in [auto, 10full, 10half, ...]>
               spillover-threshold: <value of integer>
               src-check: <value in [disable, enable]>
               status: <value in [down, up]>
               stp: <value in [disable, enable]>
               stp-ha-slave: <value in [disable, enable, priority-adjust]>
               stpforward: <value in [disable, enable]>
               stpforward-mode: <value in [rpl-all-ext-id, rpl-bridge-ext-id, rpl-nothing]>
               strip-priority-vlan-tag: <value in [disable, enable]>
               subst: <value in [disable, enable]>
               substitute-dst-mac: <value of string>
               swc-first-create: <value of integer>
               swc-vlan: <value of integer>
               switch: <value of string>
               switch-controller-access-vlan: <value in [disable, enable]>
               switch-controller-arp-inspection: <value in [disable, enable]>
               switch-controller-auth: <value in [radius, usergroup]>
               switch-controller-dhcp-snooping: <value in [disable, enable]>
               switch-controller-dhcp-snooping-option82: <value in [disable, enable]>
               switch-controller-dhcp-snooping-verify-mac: <value in [disable, enable]>
               switch-controller-feature: <value in [none, default-vlan, quarantine, ...]>
               switch-controller-igmp-snooping: <value in [disable, enable]>
               switch-controller-igmp-snooping-fast-leave: <value in [disable, enable]>
               switch-controller-igmp-snooping-proxy: <value in [disable, enable]>
               switch-controller-iot-scanning: <value in [disable, enable]>
               switch-controller-learning-limit: <value of integer>
               switch-controller-mgmt-vlan: <value of integer>
               switch-controller-nac: <value of string>
               switch-controller-radius-server: <value of string>
               switch-controller-rspan-mode: <value in [disable, enable]>
               switch-controller-source-ip: <value in [outbound, fixed]>
               switch-controller-traffic-policy: <value of string>
               tc-mode: <value in [ptm, atm]>
               tcp-mss: <value of integer>
               trunk: <value in [disable, enable]>
               trust-ip-1: <value of string>
               trust-ip-2: <value of string>
               trust-ip-3: <value of string>
               trust-ip6-1: <value of string>
               trust-ip6-2: <value of string>
               trust-ip6-3: <value of string>
               type: <value in [physical, vlan, aggregate, ...]>
               username: <value of string>
               vci: <value of integer>
               vectoring: <value in [disable, enable]>
               vindex: <value of integer>
               vlan-protocol: <value in [8021q, 8021ad]>
               vlanforward: <value in [disable, enable]>
               vlanid: <value of integer>
               vpi: <value of integer>
               vrf: <value of integer>
               vrrp:
                 -
                     accept-mode: <value in [disable, enable]>
                     adv-interval: <value of integer>
                     ignore-default-route: <value in [disable, enable]>
                     preempt: <value in [disable, enable]>
                     priority: <value of integer>
                     start-time: <value of integer>
                     status: <value in [disable, enable]>
                     version: <value in [2, 3]>
                     vrdst: <value of string>
                     vrdst-priority: <value of integer>
                     vrgrp: <value of integer>
                     vrid: <value of integer>
                     vrip: <value of string>
               vrrp-virtual-mac: <value in [disable, enable]>
               wccp: <value in [disable, enable]>
               weight: <value of integer>
               wifi-5g-threshold: <value of string>
               wifi-acl: <value in [deny, allow]>
               wifi-ap-band: <value in [any, 5g-preferred, 5g-only]>
               wifi-auth: <value in [PSK, RADIUS, radius, ...]>
               wifi-auto-connect: <value in [disable, enable]>
               wifi-auto-save: <value in [disable, enable]>
               wifi-broadcast-ssid: <value in [disable, enable]>
               wifi-encrypt: <value in [TKIP, AES]>
               wifi-fragment-threshold: <value of integer>
               wifi-key: <value of string>
               wifi-keyindex: <value of integer>
               wifi-mac-filter: <value in [disable, enable]>
               wifi-passphrase: <value of string>
               wifi-radius-server: <value of string>
               wifi-rts-threshold: <value of integer>
               wifi-security: <value in [None, WEP64, wep64, ...]>
               wifi-ssid: <value of string>
               wifi-usergroup: <value of string>
               wins-ip: <value of string>
               dhcp-relay-request-all-server: <value in [disable, enable]>
               stp-ha-secondary: <value in [disable, enable, priority-adjust]>
               switch-controller-dynamic: <value of string>
               auth-cert: <value of string>
               auth-portal-addr: <value of string>
               dhcp-classless-route-addition: <value in [disable, enable]>
               dhcp-relay-link-selection: <value of string>
               dns-server-protocol:
                 - cleartext
                 - dot
                 - doh
               eap-ca-cert: <value of string>
               eap-identity: <value of string>
               eap-method: <value in [tls, peap]>
               eap-password: <value of string>
               eap-supplicant: <value in [disable, enable]>
               eap-user-cert: <value of string>
               ike-saml-server: <value of string>
               lacp-ha-secondary: <value in [disable, enable]>
               pvc-atm-qos: <value in [cbr, rt-vbr, nrt-vbr]>
               pvc-chan: <value of integer>
               pvc-crc: <value of integer>
               pvc-pcr: <value of integer>
               pvc-scr: <value of integer>
               pvc-vlan-id: <value of integer>
               pvc-vlan-rx-id: <value of integer>
               pvc-vlan-rx-op: <value in [pass-through, replace, remove]>
               pvc-vlan-tx-id: <value of integer>
               pvc-vlan-tx-op: <value in [pass-through, replace, remove]>
               reachable-time: <value of integer>
               select-profile-30a-35b: <value in [30A, 35B]>
               sfp-dsl: <value in [disable, enable]>
               sfp-dsl-adsl-fallback: <value in [disable, enable]>
               sfp-dsl-autodetect: <value in [disable, enable]>
               sfp-dsl-mac: <value of string>
               sw-algorithm: <value in [l2, l3, eh]>
               system-id: <value of string>
               system-id-type: <value in [auto, user]>
               vlan-id: <value of integer>
               vlan-op-mode: <value in [tag, untag, passthrough]>

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
        '/pm/config/adom/{adom}/obj/fsp/vlan',
        '/pm/config/global/obj/fsp/vlan'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
        '/pm/config/global/obj/fsp/vlan/{vlan}'
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
        'fsp_vlan': {
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
                '_dhcp-status': {
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
                'auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'radius',
                        'usergroup'
                    ],
                    'type': 'str'
                },
                'color': {
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
                'comments': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'dynamic_mapping': {
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
                        '_dhcp-status': {
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
                        '_scope': {
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
                                'name': {
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
                                'vdom': {
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
                        'dhcp-server': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'auto-configuration': {
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
                                'auto-managed-status': {
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
                                'conflicted-ip-timeout': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ddns-auth': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'tsig'
                                    ],
                                    'type': 'str'
                                },
                                'ddns-key': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-keyname': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-server-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-ttl': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ddns-update': {
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
                                'ddns-update-override': {
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
                                'ddns-zone': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'default-gateway': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dhcp-settings-from-fortiipam': {
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
                                'dns-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server4': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'default',
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'domain': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'enable': {
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
                                'exclude-range': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'start-ip': {
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
                                'filename': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'forticlient-on-net-status': {
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
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip-mode': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'range',
                                        'usrgrp'
                                    ],
                                    'type': 'str'
                                },
                                'ip-range': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'start-ip': {
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
                                'ipsec-lease-hold': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'lease-time': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'mac-acl-default-action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'assign',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'netmask': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'next-server': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'default',
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'option1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'option2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'option3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'option4': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'option5': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'option6': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'options': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'code': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string',
                                                'ip',
                                                'fqdn'
                                            ],
                                            'type': 'str'
                                        },
                                        'value': {
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
                                'reserved-address': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'action': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'assign',
                                                'block',
                                                'reserved'
                                            ],
                                            'type': 'str'
                                        },
                                        'circuit-id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'circuit-id-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string'
                                            ],
                                            'type': 'str'
                                        },
                                        'description': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'mac': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'remote-id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'remote-id-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string'
                                            ],
                                            'type': 'str'
                                        },
                                        'type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'mac',
                                                'option82'
                                            ],
                                            'type': 'str'
                                        }
                                    }
                                },
                                'server-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'regular',
                                        'ipsec'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
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
                                'tftp-server': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'timezone': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        '00',
                                        '01',
                                        '02',
                                        '03',
                                        '04',
                                        '05',
                                        '06',
                                        '07',
                                        '08',
                                        '09',
                                        '10',
                                        '11',
                                        '12',
                                        '13',
                                        '14',
                                        '15',
                                        '16',
                                        '17',
                                        '18',
                                        '19',
                                        '20',
                                        '21',
                                        '22',
                                        '23',
                                        '24',
                                        '25',
                                        '26',
                                        '27',
                                        '28',
                                        '29',
                                        '30',
                                        '31',
                                        '32',
                                        '33',
                                        '34',
                                        '35',
                                        '36',
                                        '37',
                                        '38',
                                        '39',
                                        '40',
                                        '41',
                                        '42',
                                        '43',
                                        '44',
                                        '45',
                                        '46',
                                        '47',
                                        '48',
                                        '49',
                                        '50',
                                        '51',
                                        '52',
                                        '53',
                                        '54',
                                        '55',
                                        '56',
                                        '57',
                                        '58',
                                        '59',
                                        '60',
                                        '61',
                                        '62',
                                        '63',
                                        '64',
                                        '65',
                                        '66',
                                        '67',
                                        '68',
                                        '69',
                                        '70',
                                        '71',
                                        '72',
                                        '73',
                                        '74',
                                        '75',
                                        '76',
                                        '77',
                                        '78',
                                        '79',
                                        '80',
                                        '81',
                                        '82',
                                        '83',
                                        '84',
                                        '85',
                                        '86',
                                        '87'
                                    ],
                                    'type': 'str'
                                },
                                'timezone-option': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'default',
                                        'specify'
                                    ],
                                    'type': 'str'
                                },
                                'vci-match': {
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
                                'vci-string': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'wifi-ac1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'wins-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'wins-server2': {
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
                        'interface': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'dhcp-relay-agent-option': {
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
                                'dhcp-relay-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'dhcp-relay-service': {
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
                                'dhcp-relay-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'regular',
                                        'ipsec'
                                    ],
                                    'type': 'str'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'ipv6': {
                                    'required': False,
                                    'type': 'dict',
                                    'options': {
                                        'autoconf': {
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
                                        'dhcp6-client-options': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'rapid',
                                                'iapd',
                                                'iana',
                                                'dns',
                                                'dnsname'
                                            ]
                                        },
                                        'dhcp6-information-request': {
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
                                        'dhcp6-prefix-delegation': {
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
                                        'dhcp6-prefix-hint': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-hint-plt': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'dhcp6-prefix-hint-vlt': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'dhcp6-relay-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'dhcp6-relay-service': {
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
                                        'dhcp6-relay-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'regular'
                                            ],
                                            'type': 'str'
                                        },
                                        'icmp6-send-redirect': {
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
                                        'interface-identifier': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-address': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-allowaccess': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'https',
                                                'ping',
                                                'ssh',
                                                'snmp',
                                                'http',
                                                'telnet',
                                                'fgfm',
                                                'capwap',
                                                'fabric'
                                            ]
                                        },
                                        'ip6-default-life': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-delegated-prefix-list': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
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
                                                'onlink-flag': {
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
                                                'prefix-id': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'rdnss': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'rdnss-service': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'choices': [
                                                        'delegated',
                                                        'default',
                                                        'specify'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'subnet': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'upstream-interface': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'delegated-prefix-iaid': {
                                                    'required': False,
                                                    'revision': {
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                }
                                            }
                                        },
                                        'ip6-dns-server-override': {
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
                                        'ip6-extra-addr': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'prefix': {
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
                                        'ip6-hop-limit': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-link-mtu': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-manage-flag': {
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
                                        'ip6-max-interval': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-min-interval': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-mode': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'static',
                                                'dhcp',
                                                'pppoe',
                                                'delegated'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-other-flag': {
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
                                        'ip6-prefix-list': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
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
                                                'dnssl': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'onlink-flag': {
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
                                                'preferred-life-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'prefix': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'rdnss': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'valid-life-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                }
                                            }
                                        },
                                        'ip6-reachable-time': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-retrans-time': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-send-adv': {
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
                                        'ip6-subnet': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-upstream-interface': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-cert': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-cga-modifier': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-mode': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'basic',
                                                'SEND-compatible'
                                            ],
                                            'type': 'str'
                                        },
                                        'nd-security-level': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'nd-timestamp-delta': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'nd-timestamp-fuzz': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'unique-autoconf-addr': {
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
                                        'vrip6_link_local': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vrrp-virtual-mac6': {
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
                                        'vrrp6': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'accept-mode': {
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
                                                'adv-interval': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'preempt': {
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
                                                'priority': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'start-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'status': {
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
                                                'vrdst6': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'vrgrp': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'vrid': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'vrip6': {
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
                                        'cli-conn6-status': {
                                            'required': False,
                                            'revision': {
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-prefix-mode': {
                                            'required': False,
                                            'revision': {
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'choices': [
                                                'dhcp6',
                                                'ra'
                                            ],
                                            'type': 'str'
                                        },
                                        'ra-send-mtu': {
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
                                        'ip6-delegated-prefix-iaid': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        }
                                    }
                                },
                                'secondary-IP': {
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
                                'secondaryip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'allowaccess': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'https',
                                                'ping',
                                                'ssh',
                                                'snmp',
                                                'http',
                                                'telnet',
                                                'fgfm',
                                                'auto-ipsec',
                                                'radius-acct',
                                                'probe-response',
                                                'capwap',
                                                'dnp',
                                                'ftm',
                                                'fabric',
                                                'speed-test'
                                            ]
                                        },
                                        'detectprotocol': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'ping',
                                                'tcp-echo',
                                                'udp-echo'
                                            ]
                                        },
                                        'detectserver': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'gwdetect': {
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
                                        'ha-priority': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ping-serv-status': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'seq': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        }
                                    }
                                },
                                'vlanid': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'dhcp-relay-interface-select-method': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'auto',
                                        'sdwan',
                                        'specify'
                                    ],
                                    'type': 'str'
                                }
                            }
                        }
                    }
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
                'portal-message-override-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'radius-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'security': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'open',
                        'captive-portal',
                        '8021x'
                    ],
                    'type': 'str'
                },
                'selected-usergroups': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'usergroup': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'vdom': {
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
                'vlanid': {
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
                'dhcp-server': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'auto-configuration': {
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
                        'auto-managed-status': {
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
                        'conflicted-ip-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ddns-auth': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'tsig'
                            ],
                            'type': 'str'
                        },
                        'ddns-key': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-keyname': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-server-ip': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-ttl': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ddns-update': {
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
                        'ddns-update-override': {
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
                        'ddns-zone': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'default-gateway': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dhcp-settings-from-fortiipam': {
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
                        'dns-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'domain': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'enable': {
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
                        'exclude-range': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'end-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'start-ip': {
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
                        'filename': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'forticlient-on-net-status': {
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
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ip-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'range',
                                'usrgrp'
                            ],
                            'type': 'str'
                        },
                        'ip-range': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'end-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'start-ip': {
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
                        'ipsec-lease-hold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'lease-time': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mac-acl-default-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'assign',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'netmask': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'next-server': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'default',
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'option1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'option2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'option3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'option4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'option5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'option6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'code': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string',
                                        'ip',
                                        'fqdn'
                                    ],
                                    'type': 'str'
                                },
                                'value': {
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
                        'reserved-address': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'assign',
                                        'block',
                                        'reserved'
                                    ],
                                    'type': 'str'
                                },
                                'circuit-id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'circuit-id-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string'
                                    ],
                                    'type': 'str'
                                },
                                'description': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'mac': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'remote-id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'remote-id-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string'
                                    ],
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'mac',
                                        'option82'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'server-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'regular',
                                'ipsec'
                            ],
                            'type': 'str'
                        },
                        'status': {
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
                        'tftp-server': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'timezone': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                '00',
                                '01',
                                '02',
                                '03',
                                '04',
                                '05',
                                '06',
                                '07',
                                '08',
                                '09',
                                '10',
                                '11',
                                '12',
                                '13',
                                '14',
                                '15',
                                '16',
                                '17',
                                '18',
                                '19',
                                '20',
                                '21',
                                '22',
                                '23',
                                '24',
                                '25',
                                '26',
                                '27',
                                '28',
                                '29',
                                '30',
                                '31',
                                '32',
                                '33',
                                '34',
                                '35',
                                '36',
                                '37',
                                '38',
                                '39',
                                '40',
                                '41',
                                '42',
                                '43',
                                '44',
                                '45',
                                '46',
                                '47',
                                '48',
                                '49',
                                '50',
                                '51',
                                '52',
                                '53',
                                '54',
                                '55',
                                '56',
                                '57',
                                '58',
                                '59',
                                '60',
                                '61',
                                '62',
                                '63',
                                '64',
                                '65',
                                '66',
                                '67',
                                '68',
                                '69',
                                '70',
                                '71',
                                '72',
                                '73',
                                '74',
                                '75',
                                '76',
                                '77',
                                '78',
                                '79',
                                '80',
                                '81',
                                '82',
                                '83',
                                '84',
                                '85',
                                '86',
                                '87'
                            ],
                            'type': 'str'
                        },
                        'timezone-option': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'default',
                                'specify'
                            ],
                            'type': 'str'
                        },
                        'vci-match': {
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
                        'vci-string': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'wifi-ac1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wins-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'wins-server2': {
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
                'interface': {
                    'required': False,
                    'type': 'dict'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan'),
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
