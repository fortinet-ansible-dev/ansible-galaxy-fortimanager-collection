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
module: fmgr_fsp_vlan_dynamicmapping
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
    vlan:
        description: the parameter (vlan) in requested url
        type: str
        required: true
    fsp_vlan_dynamicmapping:
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
            _scope:
                description: description
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
                        description: description
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
                        description: description
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
                        description: description
                        type: str
                    option2:
                        description: description
                        type: str
                    option3:
                        description: description
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
                        description: description
                        type: list
                        suboptions:
                            code:
                                type: int
                                description: no description
                            id:
                                type: int
                                description: no description
                            ip:
                                description: description
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
                        description: description
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
                        description: description
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
                        description: description
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
                        description: description
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
                                description: description
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
                                description: description
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
                                description: description
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
                                        description: description
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
                                description: description
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
                                description: description
                                type: list
                                suboptions:
                                    autonomous-flag:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dnssl:
                                        description: description
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
                                        description: description
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
                                description: description
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
                        description: description
                        type: list
                        suboptions:
                            allowaccess:
                                description: description
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
                                description: description
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
      fmgr_fsp_vlan_dynamicmapping:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         vlan: <your own value>
         state: <value in [present, absent]>
         fsp_vlan_dynamicmapping:
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'vlan']
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
        'vlan': {
            'required': True,
            'type': 'str'
        },
        'fsp_vlan_dynamicmapping': {
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

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping'),
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
