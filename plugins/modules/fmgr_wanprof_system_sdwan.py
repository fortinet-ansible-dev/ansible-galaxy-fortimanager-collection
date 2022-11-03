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
module: fmgr_wanprof_system_sdwan
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
    wanprof:
        description: the parameter (wanprof) in requested url
        type: str
        required: true
    wanprof_system_sdwan:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            duplication:
                description: description
                type: list
                suboptions:
                    dstaddr:
                        type: str
                        description: no description
                    dstaddr6:
                        type: str
                        description: no description
                    dstintf:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    packet-de-duplication:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    packet-duplication:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'force'
                            - 'on-demand'
                    service:
                        type: str
                        description: no description
                    srcaddr:
                        type: str
                        description: no description
                    srcaddr6:
                        type: str
                        description: no description
                    srcintf:
                        type: str
                        description: no description
                    service-id:
                        type: str
                        description: no description
                    sla-match-service:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            duplication-max-num:
                type: int
                description: no description
            fail-detect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            health-check:
                description: description
                type: list
                suboptions:
                    _dynamic-server:
                        type: str
                        description: no description
                    addr-mode:
                        type: str
                        description: no description
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    diffservcode:
                        type: str
                        description: no description
                    dns-match-ip:
                        type: str
                        description: no description
                    dns-request-domain:
                        type: str
                        description: no description
                    failtime:
                        type: int
                        description: no description
                    ftp-file:
                        type: str
                        description: no description
                    ftp-mode:
                        type: str
                        description: no description
                        choices:
                            - 'passive'
                            - 'port'
                    ha-priority:
                        type: int
                        description: no description
                    http-agent:
                        type: str
                        description: no description
                    http-get:
                        type: str
                        description: no description
                    http-match:
                        type: str
                        description: no description
                    interval:
                        type: int
                        description: no description
                    members:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    packet-size:
                        type: int
                        description: no description
                    password:
                        description: description
                        type: str
                    port:
                        type: int
                        description: no description
                    probe-count:
                        type: int
                        description: no description
                    probe-packets:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    probe-timeout:
                        type: int
                        description: no description
                    protocol:
                        type: str
                        description: no description
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                            - 'twamp'
                            - 'ping6'
                            - 'dns'
                            - 'tcp-connect'
                            - 'ftp'
                    quality-measured-method:
                        type: str
                        description: no description
                        choices:
                            - 'half-close'
                            - 'half-open'
                    recoverytime:
                        type: int
                        description: no description
                    security-mode:
                        type: str
                        description: no description
                        choices:
                            - 'none'
                            - 'authentication'
                    server:
                        description: description
                        type: str
                    sla:
                        description: description
                        type: list
                        suboptions:
                            id:
                                type: int
                                description: no description
                            jitter-threshold:
                                type: int
                                description: no description
                            latency-threshold:
                                type: int
                                description: no description
                            link-cost-factor:
                                description: description
                                type: list
                                choices:
                                 - latency
                                 - jitter
                                 - packet-loss
                                 - mos
                            packetloss-threshold:
                                type: int
                                description: no description
                            mos-threshold:
                                type: str
                                description: no description
                    sla-fail-log-period:
                        type: int
                        description: no description
                    sla-pass-log-period:
                        type: int
                        description: no description
                    system-dns:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    threshold-alert-jitter:
                        type: int
                        description: no description
                    threshold-alert-latency:
                        type: int
                        description: no description
                    threshold-alert-packetloss:
                        type: int
                        description: no description
                    threshold-warning-jitter:
                        type: int
                        description: no description
                    threshold-warning-latency:
                        type: int
                        description: no description
                    threshold-warning-packetloss:
                        type: int
                        description: no description
                    update-cascade-interface:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    update-static-route:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    user:
                        type: str
                        description: no description
                    detect-mode:
                        type: str
                        description: no description
                        choices:
                            - 'active'
                            - 'passive'
                            - 'prefer-passive'
                    mos-codec:
                        type: str
                        description: no description
                        choices:
                            - 'g711'
                            - 'g722'
                            - 'g729'
                    source:
                        type: str
                        description: no description
                    vrf:
                        type: int
                        description: no description
            load-balance-mode:
                type: str
                description: no description
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
                    - 'measured-volume-based'
            members:
                description: description
                type: list
                suboptions:
                    _dynamic-member:
                        type: str
                        description: no description
                    comment:
                        type: str
                        description: no description
                    cost:
                        type: int
                        description: no description
                    gateway:
                        type: str
                        description: no description
                    gateway6:
                        type: str
                        description: no description
                    ingress-spillover-threshold:
                        type: int
                        description: no description
                    interface:
                        type: str
                        description: no description
                    priority:
                        type: int
                        description: no description
                    seq-num:
                        type: int
                        description: no description
                    source:
                        type: str
                        description: no description
                    source6:
                        type: str
                        description: no description
                    spillover-threshold:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    volume-ratio:
                        type: int
                        description: no description
                    weight:
                        type: int
                        description: no description
                    zone:
                        type: str
                        description: no description
                    priority6:
                        type: int
                        description: no description
            neighbor:
                description: description
                type: list
                suboptions:
                    health-check:
                        type: str
                        description: no description
                    ip:
                        type: str
                        description: no description
                    member:
                        type: str
                        description: no description
                    role:
                        type: str
                        description: no description
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    sla-id:
                        type: int
                        description: no description
                    minimum-sla-meet-members:
                        type: int
                        description: no description
                    mode:
                        type: str
                        description: no description
                        choices:
                            - 'sla'
                            - 'speedtest'
            neighbor-hold-boot-time:
                type: int
                description: no description
            neighbor-hold-down:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            neighbor-hold-down-time:
                type: int
                description: no description
            service:
                description: description
                type: list
                suboptions:
                    addr-mode:
                        type: str
                        description: no description
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    bandwidth-weight:
                        type: int
                        description: no description
                    default:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp-forward:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp-forward-tag:
                        type: str
                        description: no description
                    dscp-reverse:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp-reverse-tag:
                        type: str
                        description: no description
                    dst:
                        type: str
                        description: no description
                    dst-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    dst6:
                        type: str
                        description: no description
                    end-port:
                        type: int
                        description: no description
                    gateway:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: no description
                    hash-mode:
                        type: str
                        description: no description
                        choices:
                            - 'round-robin'
                            - 'source-ip-based'
                            - 'source-dest-ip-based'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                    health-check:
                        type: str
                        description: no description
                    hold-down-time:
                        type: int
                        description: no description
                    id:
                        type: int
                        description: no description
                    input-device:
                        type: str
                        description: no description
                    input-device-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    internet-service:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    internet-service-app-ctrl:
                        description: description
                        type: int
                    internet-service-app-ctrl-group:
                        type: str
                        description: no description
                    internet-service-custom:
                        type: str
                        description: no description
                    internet-service-custom-group:
                        type: str
                        description: no description
                    internet-service-group:
                        type: str
                        description: no description
                    internet-service-name:
                        type: str
                        description: no description
                    jitter-weight:
                        type: int
                        description: no description
                    latency-weight:
                        type: int
                        description: no description
                    link-cost-factor:
                        type: str
                        description: no description
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                            - 'custom-profile-1'
                    link-cost-threshold:
                        type: int
                        description: no description
                    minimum-sla-meet-members:
                        type: int
                        description: no description
                    mode:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'manual'
                            - 'priority'
                            - 'sla'
                            - 'load-balance'
                    name:
                        type: str
                        description: no description
                    packet-loss-weight:
                        type: int
                        description: no description
                    priority-members:
                        type: str
                        description: no description
                    protocol:
                        type: int
                        description: no description
                    quality-link:
                        type: int
                        description: no description
                    role:
                        type: str
                        description: no description
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    route-tag:
                        type: int
                        description: no description
                    sla:
                        description: description
                        type: list
                        suboptions:
                            health-check:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                    sla-compare-method:
                        type: str
                        description: no description
                        choices:
                            - 'order'
                            - 'number'
                    src:
                        type: str
                        description: no description
                    src-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    src6:
                        type: str
                        description: no description
                    standalone-action:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    start-port:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    tos:
                        type: str
                        description: no description
                    tos-mask:
                        type: str
                        description: no description
                    users:
                        type: str
                        description: no description
                    tie-break:
                        type: str
                        description: no description
                        choices:
                            - 'zone'
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'input-device'
                    use-shortcut-sla:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    input-zone:
                        description: description
                        type: str
                    internet-service-app-ctrl-category:
                        description: description
                        type: int
                    passive-measurement:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    priority-zone:
                        description: description
                        type: str
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            zone:
                description: description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    service-sla-tie-break:
                        type: str
                        description: no description
                        choices:
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'input-device'
            speedtest-bypass-routing:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'

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
      fmgr_wanprof_system_sdwan:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wanprof: <your own value>
         wanprof_system_sdwan:
            duplication:
              -
                  dstaddr: <value of string>
                  dstaddr6: <value of string>
                  dstintf: <value of string>
                  id: <value of integer>
                  packet-de-duplication: <value in [disable, enable]>
                  packet-duplication: <value in [disable, force, on-demand]>
                  service: <value of string>
                  srcaddr: <value of string>
                  srcaddr6: <value of string>
                  srcintf: <value of string>
                  service-id: <value of string>
                  sla-match-service: <value in [disable, enable]>
            duplication-max-num: <value of integer>
            fail-detect: <value in [disable, enable]>
            health-check:
              -
                  _dynamic-server: <value of string>
                  addr-mode: <value in [ipv4, ipv6]>
                  diffservcode: <value of string>
                  dns-match-ip: <value of string>
                  dns-request-domain: <value of string>
                  failtime: <value of integer>
                  ftp-file: <value of string>
                  ftp-mode: <value in [passive, port]>
                  ha-priority: <value of integer>
                  http-agent: <value of string>
                  http-get: <value of string>
                  http-match: <value of string>
                  interval: <value of integer>
                  members: <value of string>
                  name: <value of string>
                  packet-size: <value of integer>
                  password: <value of string>
                  port: <value of integer>
                  probe-count: <value of integer>
                  probe-packets: <value in [disable, enable]>
                  probe-timeout: <value of integer>
                  protocol: <value in [ping, tcp-echo, udp-echo, ...]>
                  quality-measured-method: <value in [half-close, half-open]>
                  recoverytime: <value of integer>
                  security-mode: <value in [none, authentication]>
                  server: <value of string>
                  sla:
                    -
                        id: <value of integer>
                        jitter-threshold: <value of integer>
                        latency-threshold: <value of integer>
                        link-cost-factor:
                          - latency
                          - jitter
                          - packet-loss
                          - mos
                        packetloss-threshold: <value of integer>
                        mos-threshold: <value of string>
                  sla-fail-log-period: <value of integer>
                  sla-pass-log-period: <value of integer>
                  system-dns: <value in [disable, enable]>
                  threshold-alert-jitter: <value of integer>
                  threshold-alert-latency: <value of integer>
                  threshold-alert-packetloss: <value of integer>
                  threshold-warning-jitter: <value of integer>
                  threshold-warning-latency: <value of integer>
                  threshold-warning-packetloss: <value of integer>
                  update-cascade-interface: <value in [disable, enable]>
                  update-static-route: <value in [disable, enable]>
                  user: <value of string>
                  detect-mode: <value in [active, passive, prefer-passive]>
                  mos-codec: <value in [g711, g722, g729]>
                  source: <value of string>
                  vrf: <value of integer>
            load-balance-mode: <value in [source-ip-based, weight-based, usage-based, ...]>
            members:
              -
                  _dynamic-member: <value of string>
                  comment: <value of string>
                  cost: <value of integer>
                  gateway: <value of string>
                  gateway6: <value of string>
                  ingress-spillover-threshold: <value of integer>
                  interface: <value of string>
                  priority: <value of integer>
                  seq-num: <value of integer>
                  source: <value of string>
                  source6: <value of string>
                  spillover-threshold: <value of integer>
                  status: <value in [disable, enable]>
                  volume-ratio: <value of integer>
                  weight: <value of integer>
                  zone: <value of string>
                  priority6: <value of integer>
            neighbor:
              -
                  health-check: <value of string>
                  ip: <value of string>
                  member: <value of string>
                  role: <value in [primary, secondary, standalone]>
                  sla-id: <value of integer>
                  minimum-sla-meet-members: <value of integer>
                  mode: <value in [sla, speedtest]>
            neighbor-hold-boot-time: <value of integer>
            neighbor-hold-down: <value in [disable, enable]>
            neighbor-hold-down-time: <value of integer>
            service:
              -
                  addr-mode: <value in [ipv4, ipv6]>
                  bandwidth-weight: <value of integer>
                  default: <value in [disable, enable]>
                  dscp-forward: <value in [disable, enable]>
                  dscp-forward-tag: <value of string>
                  dscp-reverse: <value in [disable, enable]>
                  dscp-reverse-tag: <value of string>
                  dst: <value of string>
                  dst-negate: <value in [disable, enable]>
                  dst6: <value of string>
                  end-port: <value of integer>
                  gateway: <value in [disable, enable]>
                  groups: <value of string>
                  hash-mode: <value in [round-robin, source-ip-based, source-dest-ip-based, ...]>
                  health-check: <value of string>
                  hold-down-time: <value of integer>
                  id: <value of integer>
                  input-device: <value of string>
                  input-device-negate: <value in [disable, enable]>
                  internet-service: <value in [disable, enable]>
                  internet-service-app-ctrl: <value of integer>
                  internet-service-app-ctrl-group: <value of string>
                  internet-service-custom: <value of string>
                  internet-service-custom-group: <value of string>
                  internet-service-group: <value of string>
                  internet-service-name: <value of string>
                  jitter-weight: <value of integer>
                  latency-weight: <value of integer>
                  link-cost-factor: <value in [latency, jitter, packet-loss, ...]>
                  link-cost-threshold: <value of integer>
                  minimum-sla-meet-members: <value of integer>
                  mode: <value in [auto, manual, priority, ...]>
                  name: <value of string>
                  packet-loss-weight: <value of integer>
                  priority-members: <value of string>
                  protocol: <value of integer>
                  quality-link: <value of integer>
                  role: <value in [primary, secondary, standalone]>
                  route-tag: <value of integer>
                  sla:
                    -
                        health-check: <value of string>
                        id: <value of integer>
                  sla-compare-method: <value in [order, number]>
                  src: <value of string>
                  src-negate: <value in [disable, enable]>
                  src6: <value of string>
                  standalone-action: <value in [disable, enable]>
                  start-port: <value of integer>
                  status: <value in [disable, enable]>
                  tos: <value of string>
                  tos-mask: <value of string>
                  users: <value of string>
                  tie-break: <value in [zone, cfg-order, fib-best-match, ...]>
                  use-shortcut-sla: <value in [disable, enable]>
                  input-zone: <value of string>
                  internet-service-app-ctrl-category: <value of integer>
                  passive-measurement: <value in [disable, enable]>
                  priority-zone: <value of string>
            status: <value in [disable, enable]>
            zone:
              -
                  name: <value of string>
                  service-sla-tie-break: <value in [cfg-order, fib-best-match, input-device]>
            speedtest-bypass-routing: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/{sdwan}'
    ]

    url_params = ['adom', 'wanprof']
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
        'wanprof': {
            'required': True,
            'type': 'str'
        },
        'wanprof_system_sdwan': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'duplication': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'dstaddr': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dstaddr6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dstintf': {
                            'required': False,
                            'revision': {
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
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'packet-de-duplication': {
                            'required': False,
                            'revision': {
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
                        'packet-duplication': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'force',
                                'on-demand'
                            ],
                            'type': 'str'
                        },
                        'service': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'srcaddr': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'srcaddr6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'srcintf': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'service-id': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'sla-match-service': {
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
                'duplication-max-num': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'fail-detect': {
                    'required': False,
                    'revision': {
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
                'health-check': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        '_dynamic-server': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'addr-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'ipv4',
                                'ipv6'
                            ],
                            'type': 'str'
                        },
                        'diffservcode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-match-ip': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-request-domain': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'failtime': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ftp-file': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ftp-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'passive',
                                'port'
                            ],
                            'type': 'str'
                        },
                        'ha-priority': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'http-agent': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'http-get': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'http-match': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'interval': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'members': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'packet-size': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'password': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'probe-count': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'probe-packets': {
                            'required': False,
                            'revision': {
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
                        'probe-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'protocol': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'ping',
                                'tcp-echo',
                                'udp-echo',
                                'http',
                                'twamp',
                                'ping6',
                                'dns',
                                'tcp-connect',
                                'ftp'
                            ],
                            'type': 'str'
                        },
                        'quality-measured-method': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'half-close',
                                'half-open'
                            ],
                            'type': 'str'
                        },
                        'recoverytime': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'security-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'none',
                                'authentication'
                            ],
                            'type': 'str'
                        },
                        'server': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'sla': {
                            'required': False,
                            'revision': {
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
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'jitter-threshold': {
                                    'required': False,
                                    'revision': {
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'latency-threshold': {
                                    'required': False,
                                    'revision': {
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'link-cost-factor': {
                                    'required': False,
                                    'revision': {
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'choices': [
                                        'latency',
                                        'jitter',
                                        'packet-loss',
                                        'mos'
                                    ]
                                },
                                'packetloss-threshold': {
                                    'required': False,
                                    'revision': {
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'mos-threshold': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                }
                            }
                        },
                        'sla-fail-log-period': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'sla-pass-log-period': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'system-dns': {
                            'required': False,
                            'revision': {
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
                        'threshold-alert-jitter': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'threshold-alert-latency': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'threshold-alert-packetloss': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'threshold-warning-jitter': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'threshold-warning-latency': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'threshold-warning-packetloss': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'update-cascade-interface': {
                            'required': False,
                            'revision': {
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
                        'update-static-route': {
                            'required': False,
                            'revision': {
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
                        'user': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'detect-mode': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'active',
                                'passive',
                                'prefer-passive'
                            ],
                            'type': 'str'
                        },
                        'mos-codec': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'g711',
                                'g722',
                                'g729'
                            ],
                            'type': 'str'
                        },
                        'source': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vrf': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'load-balance-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'source-ip-based',
                        'weight-based',
                        'usage-based',
                        'source-dest-ip-based',
                        'measured-volume-based'
                    ],
                    'type': 'str'
                },
                'members': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        '_dynamic-member': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'str'
                        },
                        'comment': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cost': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'gateway': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'gateway6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ingress-spillover-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'interface': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'seq-num': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'source': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'source6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'spillover-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'revision': {
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
                        'volume-ratio': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'weight': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'zone': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'priority6': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'neighbor': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'health-check': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'member': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'role': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'primary',
                                'secondary',
                                'standalone'
                            ],
                            'type': 'str'
                        },
                        'sla-id': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'minimum-sla-meet-members': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mode': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'sla',
                                'speedtest'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'neighbor-hold-boot-time': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'neighbor-hold-down': {
                    'required': False,
                    'revision': {
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
                'neighbor-hold-down-time': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'service': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'addr-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'ipv4',
                                'ipv6'
                            ],
                            'type': 'str'
                        },
                        'bandwidth-weight': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'default': {
                            'required': False,
                            'revision': {
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
                        'dscp-forward': {
                            'required': False,
                            'revision': {
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
                        'dscp-forward-tag': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dscp-reverse': {
                            'required': False,
                            'revision': {
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
                        'dscp-reverse-tag': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dst': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dst-negate': {
                            'required': False,
                            'revision': {
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
                        'dst6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'end-port': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'gateway': {
                            'required': False,
                            'revision': {
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
                        'groups': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'hash-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'round-robin',
                                'source-ip-based',
                                'source-dest-ip-based',
                                'inbandwidth',
                                'outbandwidth',
                                'bibandwidth'
                            ],
                            'type': 'str'
                        },
                        'health-check': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'hold-down-time': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'input-device': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'input-device-negate': {
                            'required': False,
                            'revision': {
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
                        'internet-service': {
                            'required': False,
                            'revision': {
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
                        'internet-service-app-ctrl': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'internet-service-app-ctrl-group': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'internet-service-custom': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'internet-service-custom-group': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'internet-service-group': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'internet-service-name': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'jitter-weight': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'latency-weight': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'link-cost-factor': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'latency',
                                'jitter',
                                'packet-loss',
                                'inbandwidth',
                                'outbandwidth',
                                'bibandwidth',
                                'custom-profile-1'
                            ],
                            'type': 'str'
                        },
                        'link-cost-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'minimum-sla-meet-members': {
                            'required': False,
                            'revision': {
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
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'auto',
                                'manual',
                                'priority',
                                'sla',
                                'load-balance'
                            ],
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'packet-loss-weight': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'priority-members': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'protocol': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'quality-link': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'role': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'primary',
                                'secondary',
                                'standalone'
                            ],
                            'type': 'str'
                        },
                        'route-tag': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'sla': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'health-check': {
                                    'required': False,
                                    'revision': {
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
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                }
                            }
                        },
                        'sla-compare-method': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'order',
                                'number'
                            ],
                            'type': 'str'
                        },
                        'src': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'src-negate': {
                            'required': False,
                            'revision': {
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
                        'src6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'standalone-action': {
                            'required': False,
                            'revision': {
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
                        'start-port': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'revision': {
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
                        'tos': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'tos-mask': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'users': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'tie-break': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'zone',
                                'cfg-order',
                                'fib-best-match',
                                'input-device'
                            ],
                            'type': 'str'
                        },
                        'use-shortcut-sla': {
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
                        'input-zone': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'internet-service-app-ctrl-category': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'passive-measurement': {
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
                        'priority-zone': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'status': {
                    'required': False,
                    'revision': {
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
                'zone': {
                    'required': False,
                    'revision': {
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
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'service-sla-tie-break': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'cfg-order',
                                'fib-best-match',
                                'input-device'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'speedtest-bypass-routing': {
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

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan'),
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
