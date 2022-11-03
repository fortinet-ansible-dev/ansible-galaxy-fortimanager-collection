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
module: fmgr_pm_config_pblock_firewall_policy
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
    pblock:
        description: the parameter (pblock) in requested url
        type: str
        required: true
    pm_config_pblock_firewall_policy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _policy_block:
                type: int
                description: no description
            action:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
                    - 'redirect'
                    - 'isolate'
            anti-replay:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            application-list:
                type: str
                description: no description
            auth-cert:
                type: str
                description: no description
            auth-path:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auth-redirect-addr:
                type: str
                description: no description
            auto-asic-offload:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            av-profile:
                type: str
                description: no description
            block-notification:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            captive-portal-exempt:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            capture-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            cifs-profile:
                type: str
                description: no description
            comments:
                type: str
                description: no description
            custom-log-fields:
                description: description
                type: str
            decrypted-traffic-mirror:
                type: str
                description: no description
            delay-tcp-npu-session:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-forward:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-reverse:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode-forward:
                type: str
                description: no description
            diffservcode-rev:
                type: str
                description: no description
            disclaimer:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'user'
                    - 'domain'
                    - 'policy'
            dlp-profile:
                type: str
                description: no description
            dnsfilter-profile:
                type: str
                description: no description
            dsri:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                description: description
                type: str
            dstaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                description: description
                type: str
            dstintf:
                description: description
                type: str
            dynamic-shaping:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            email-collect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter-profile:
                type: str
                description: no description
            fec:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            file-filter-profile:
                type: str
                description: no description
            firewall-session-dirty:
                type: str
                description: no description
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            fsso-agent-for-ntlm:
                type: str
                description: no description
            fsso-groups:
                description: description
                type: str
            geoip-anycast:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            geoip-match:
                type: str
                description: no description
                choices:
                    - 'physical-location'
                    - 'registered-location'
            global-label:
                type: str
                description: no description
            groups:
                description: description
                type: str
            gtp-profile:
                type: str
                description: no description
            http-policy-redirect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            icap-profile:
                type: str
                description: no description
            identity-based-route:
                type: str
                description: no description
            inbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            inspection-mode:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow'
            internet-service:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                description: description
                type: str
            internet-service-custom-group:
                description: description
                type: str
            internet-service-group:
                description: description
                type: str
            internet-service-name:
                description: description
                type: str
            internet-service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                description: description
                type: str
            internet-service-src-custom-group:
                description: description
                type: str
            internet-service-src-group:
                description: description
                type: str
            internet-service-src-name:
                description: description
                type: str
            internet-service-src-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: no description
            label:
                type: str
                description: no description
            logtraffic:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic-start:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            match-vip:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            match-vip-only:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: no description
            nat:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            nat46:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            natip:
                type: str
                description: no description
            natoutbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            np-acceleration:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ntlm:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ntlm-enabled-browsers:
                description: description
                type: str
            ntlm-guest:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            passive-wan-health-measurement:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: no description
            permit-any-host:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            permit-stun-host:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            pfcp-profile:
                type: str
                description: no description
            policy-expiry:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            policy-expiry-date:
                type: str
                description: no description
            policyid:
                type: int
                description: no description
            poolname:
                description: description
                type: str
            poolname6:
                description: description
                type: str
            profile-group:
                type: str
                description: no description
            profile-protocol-options:
                type: str
                description: no description
            profile-type:
                type: str
                description: no description
                choices:
                    - 'single'
                    - 'group'
            radius-mac-auth-bypass:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            redirect-url:
                type: str
                description: no description
            replacemsg-override-group:
                type: str
                description: no description
            reputation-direction:
                type: str
                description: no description
                choices:
                    - 'source'
                    - 'destination'
            reputation-minimum:
                type: int
                description: no description
            rtp-addr:
                description: description
                type: str
            rtp-nat:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            schedule:
                type: str
                description: no description
            schedule-timeout:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sctp-filter-profile:
                type: str
                description: no description
            send-deny-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            service:
                description: description
                type: str
            service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            session-ttl:
                type: int
                description: no description
            sgt:
                description: description
                type: int
            sgt-check:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            src-vendor-mac:
                description: description
                type: str
            srcaddr:
                description: description
                type: str
            srcaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                description: description
                type: str
            srcintf:
                description: description
                type: str
            ssh-filter-profile:
                type: str
                description: no description
            ssh-policy-redirect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-ssh-profile:
                type: str
                description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tcp-mss-receiver:
                type: int
                description: no description
            tcp-mss-sender:
                type: int
                description: no description
            tcp-session-without-syn:
                type: str
                description: no description
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout-send-rst:
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
            tos-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: no description
            traffic-shaper-reverse:
                type: str
                description: no description
            users:
                description: description
                type: str
            utm-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: no description
            videofilter-profile:
                type: str
                description: no description
            vlan-cos-fwd:
                type: int
                description: no description
            vlan-cos-rev:
                type: int
                description: no description
            vlan-filter:
                type: str
                description: no description
            voip-profile:
                type: str
                description: no description
            vpntunnel:
                type: str
                description: no description
            waf-profile:
                type: str
                description: no description
            wanopt:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            wanopt-detection:
                type: str
                description: no description
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt-passive-opt:
                type: str
                description: no description
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt-peer:
                type: str
                description: no description
            wanopt-profile:
                type: str
                description: no description
            wccp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            webcache-https:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'ssl-server'
                    - 'any'
                    - 'enable'
            webfilter-profile:
                type: str
                description: no description
            webproxy-forward-server:
                type: str
                description: no description
            webproxy-profile:
                type: str
                description: no description
            ztna-ems-tag:
                description: description
                type: str
            ztna-geo-tag:
                description: description
                type: str
            ztna-status:
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
      fmgr_pm_config_pblock_firewall_policy:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pblock: <your own value>
         state: <value in [present, absent]>
         pm_config_pblock_firewall_policy:
            _policy_block: <value of integer>
            action: <value in [deny, accept, ipsec, ...]>
            anti-replay: <value in [disable, enable]>
            application-list: <value of string>
            auth-cert: <value of string>
            auth-path: <value in [disable, enable]>
            auth-redirect-addr: <value of string>
            auto-asic-offload: <value in [disable, enable]>
            av-profile: <value of string>
            block-notification: <value in [disable, enable]>
            captive-portal-exempt: <value in [disable, enable]>
            capture-packet: <value in [disable, enable]>
            cifs-profile: <value of string>
            comments: <value of string>
            custom-log-fields: <value of string>
            decrypted-traffic-mirror: <value of string>
            delay-tcp-npu-session: <value in [disable, enable]>
            diffserv-forward: <value in [disable, enable]>
            diffserv-reverse: <value in [disable, enable]>
            diffservcode-forward: <value of string>
            diffservcode-rev: <value of string>
            disclaimer: <value in [disable, enable, user, ...]>
            dlp-profile: <value of string>
            dnsfilter-profile: <value of string>
            dsri: <value in [disable, enable]>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            dstaddr6: <value of string>
            dstintf: <value of string>
            dynamic-shaping: <value in [disable, enable]>
            email-collect: <value in [disable, enable]>
            emailfilter-profile: <value of string>
            fec: <value in [disable, enable]>
            file-filter-profile: <value of string>
            firewall-session-dirty: <value in [check-all, check-new]>
            fixedport: <value in [disable, enable]>
            fsso-agent-for-ntlm: <value of string>
            fsso-groups: <value of string>
            geoip-anycast: <value in [disable, enable]>
            geoip-match: <value in [physical-location, registered-location]>
            global-label: <value of string>
            groups: <value of string>
            gtp-profile: <value of string>
            http-policy-redirect: <value in [disable, enable]>
            icap-profile: <value of string>
            identity-based-route: <value of string>
            inbound: <value in [disable, enable]>
            inspection-mode: <value in [proxy, flow]>
            internet-service: <value in [disable, enable]>
            internet-service-custom: <value of string>
            internet-service-custom-group: <value of string>
            internet-service-group: <value of string>
            internet-service-name: <value of string>
            internet-service-negate: <value in [disable, enable]>
            internet-service-src: <value in [disable, enable]>
            internet-service-src-custom: <value of string>
            internet-service-src-custom-group: <value of string>
            internet-service-src-group: <value of string>
            internet-service-src-name: <value of string>
            internet-service-src-negate: <value in [disable, enable]>
            ippool: <value in [disable, enable]>
            ips-sensor: <value of string>
            label: <value of string>
            logtraffic: <value in [disable, enable, all, ...]>
            logtraffic-start: <value in [disable, enable]>
            match-vip: <value in [disable, enable]>
            match-vip-only: <value in [disable, enable]>
            name: <value of string>
            nat: <value in [disable, enable]>
            nat46: <value in [disable, enable]>
            nat64: <value in [disable, enable]>
            natinbound: <value in [disable, enable]>
            natip: <value of string>
            natoutbound: <value in [disable, enable]>
            np-acceleration: <value in [disable, enable]>
            ntlm: <value in [disable, enable]>
            ntlm-enabled-browsers: <value of string>
            ntlm-guest: <value in [disable, enable]>
            outbound: <value in [disable, enable]>
            passive-wan-health-measurement: <value in [disable, enable]>
            per-ip-shaper: <value of string>
            permit-any-host: <value in [disable, enable]>
            permit-stun-host: <value in [disable, enable]>
            pfcp-profile: <value of string>
            policy-expiry: <value in [disable, enable]>
            policy-expiry-date: <value of string>
            policyid: <value of integer>
            poolname: <value of string>
            poolname6: <value of string>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            radius-mac-auth-bypass: <value in [disable, enable]>
            redirect-url: <value of string>
            replacemsg-override-group: <value of string>
            reputation-direction: <value in [source, destination]>
            reputation-minimum: <value of integer>
            rtp-addr: <value of string>
            rtp-nat: <value in [disable, enable]>
            schedule: <value of string>
            schedule-timeout: <value in [disable, enable]>
            sctp-filter-profile: <value of string>
            send-deny-packet: <value in [disable, enable]>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            session-ttl: <value of integer>
            sgt: <value of integer>
            sgt-check: <value in [disable, enable]>
            src-vendor-mac: <value of string>
            srcaddr: <value of string>
            srcaddr-negate: <value in [disable, enable]>
            srcaddr6: <value of string>
            srcintf: <value of string>
            ssh-filter-profile: <value of string>
            ssh-policy-redirect: <value in [disable, enable]>
            ssl-ssh-profile: <value of string>
            status: <value in [disable, enable]>
            tcp-mss-receiver: <value of integer>
            tcp-mss-sender: <value of integer>
            tcp-session-without-syn: <value in [all, data-only, disable]>
            timeout-send-rst: <value in [disable, enable]>
            tos: <value of string>
            tos-mask: <value of string>
            tos-negate: <value in [disable, enable]>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            users: <value of string>
            utm-status: <value in [disable, enable]>
            uuid: <value of string>
            videofilter-profile: <value of string>
            vlan-cos-fwd: <value of integer>
            vlan-cos-rev: <value of integer>
            vlan-filter: <value of string>
            voip-profile: <value of string>
            vpntunnel: <value of string>
            waf-profile: <value of string>
            wanopt: <value in [disable, enable]>
            wanopt-detection: <value in [active, passive, off]>
            wanopt-passive-opt: <value in [default, transparent, non-transparent]>
            wanopt-peer: <value of string>
            wanopt-profile: <value of string>
            wccp: <value in [disable, enable]>
            webcache: <value in [disable, enable]>
            webcache-https: <value in [disable, ssl-server, any, ...]>
            webfilter-profile: <value of string>
            webproxy-forward-server: <value of string>
            webproxy-profile: <value of string>
            ztna-ems-tag: <value of string>
            ztna-geo-tag: <value of string>
            ztna-status: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
    ]

    url_params = ['adom', 'pblock']
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
        'pblock': {
            'required': True,
            'type': 'str'
        },
        'pm_config_pblock_firewall_policy': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                '_policy_block': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'deny',
                        'accept',
                        'ipsec',
                        'ssl-vpn',
                        'redirect',
                        'isolate'
                    ],
                    'type': 'str'
                },
                'anti-replay': {
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
                'application-list': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'auth-cert': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'auth-path': {
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
                'auth-redirect-addr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'auto-asic-offload': {
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
                'av-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'block-notification': {
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
                'captive-portal-exempt': {
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
                'capture-packet': {
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
                'cifs-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'custom-log-fields': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'decrypted-traffic-mirror': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'delay-tcp-npu-session': {
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
                'diffserv-forward': {
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
                'diffserv-reverse': {
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
                'diffservcode-forward': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'diffservcode-rev': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'disclaimer': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'user',
                        'domain',
                        'policy'
                    ],
                    'type': 'str'
                },
                'dlp-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dnsfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dsri': {
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
                'dstaddr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dstaddr-negate': {
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
                'dstaddr6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dynamic-shaping': {
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
                'email-collect': {
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
                'emailfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'fec': {
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
                'file-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'firewall-session-dirty': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'check-all',
                        'check-new'
                    ],
                    'type': 'str'
                },
                'fixedport': {
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
                'fsso-agent-for-ntlm': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'fsso-groups': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'geoip-anycast': {
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
                'geoip-match': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'physical-location',
                        'registered-location'
                    ],
                    'type': 'str'
                },
                'global-label': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'gtp-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'http-policy-redirect': {
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
                'icap-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'identity-based-route': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'inbound': {
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
                'inspection-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'internet-service': {
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
                'internet-service-custom': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-negate': {
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
                'internet-service-src': {
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
                'internet-service-src-custom': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-negate': {
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
                'ippool': {
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
                'ips-sensor': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'label': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'logtraffic-start': {
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
                'match-vip': {
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
                'match-vip-only': {
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
                'name': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'nat': {
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
                'nat46': {
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
                'nat64': {
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
                'natinbound': {
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
                'natip': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'natoutbound': {
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
                'np-acceleration': {
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
                'ntlm': {
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
                'ntlm-enabled-browsers': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ntlm-guest': {
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
                'outbound': {
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
                'passive-wan-health-measurement': {
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
                'per-ip-shaper': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'permit-any-host': {
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
                'permit-stun-host': {
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
                'pfcp-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'policy-expiry': {
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
                'policy-expiry-date': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'policyid': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'poolname': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'poolname6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'profile-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'radius-mac-auth-bypass': {
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
                'redirect-url': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'replacemsg-override-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'reputation-direction': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'source',
                        'destination'
                    ],
                    'type': 'str'
                },
                'reputation-minimum': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'rtp-addr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'rtp-nat': {
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
                'schedule': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'schedule-timeout': {
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
                'sctp-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'send-deny-packet': {
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
                'service': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'service-negate': {
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
                'session-ttl': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'sgt': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'sgt-check': {
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
                'src-vendor-mac': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'srcaddr-negate': {
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
                'srcaddr6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'srcintf': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ssh-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ssh-policy-redirect': {
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
                'ssl-ssh-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'status': {
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
                'tcp-mss-receiver': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'tcp-mss-sender': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'tcp-session-without-syn': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'all',
                        'data-only',
                        'disable'
                    ],
                    'type': 'str'
                },
                'timeout-send-rst': {
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
                'tos': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'tos-mask': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'tos-negate': {
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
                'traffic-shaper': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'traffic-shaper-reverse': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'utm-status': {
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
                'uuid': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'videofilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vlan-cos-fwd': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'vlan-cos-rev': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'vlan-filter': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'voip-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vpntunnel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'waf-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wanopt': {
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
                'wanopt-detection': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'active',
                        'passive',
                        'off'
                    ],
                    'type': 'str'
                },
                'wanopt-passive-opt': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'default',
                        'transparent',
                        'non-transparent'
                    ],
                    'type': 'str'
                },
                'wanopt-peer': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wanopt-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wccp': {
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
                'webcache': {
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
                'webcache-https': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'ssl-server',
                        'any',
                        'enable'
                    ],
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'webproxy-forward-server': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'webproxy-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ztna-ems-tag': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ztna-geo-tag': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ztna-status': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_config_pblock_firewall_policy'),
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
