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
module: fmgr_pkg_header_policy6
short_description: no description
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_header_policy6:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
            anti-replay:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            app-category:
                type: str
                description: no description
            app-group:
                type: str
                description: no description
            application:
                description: no description
                type: int
            application-charts:
                description: no description
                type: list
                choices:
                 - top10-app
                 - top10-p2p-user
                 - top10-media-user
            application-list:
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
            casi-profile:
                type: str
                description: no description
            cifs-profile:
                type: str
                description: no description
            comments:
                type: str
                description: no description
            custom-log-fields:
                type: str
                description: no description
            deep-inspection-options:
                type: str
                description: no description
            device-detection-portal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            devices:
                type: str
                description: no description
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
            dlp-sensor:
                type: str
                description: no description
            dnsfilter-profile:
                type: str
                description: no description
            dscp-match:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dscp-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dscp-value:
                type: str
                description: no description
            dsri:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: str
                description: no description
            dstaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: str
                description: no description
            dynamic-profile:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile-access:
                description: no description
                type: list
                choices:
                 - imap
                 - smtp
                 - pop3
                 - http
                 - ftp
                 - im
                 - nntp
                 - imaps
                 - smtps
                 - pop3s
                 - https
                 - ftps
            dynamic-profile-group:
                type: str
                description: no description
            email-collection-portal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter-profile:
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
            fsae:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            global-label:
                type: str
                description: no description
            groups:
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
            identity-based:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            identity-based-policy6:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: no description
                        choices:
                            - 'deny'
                            - 'accept'
                    application-list:
                        type: str
                        description: no description
                    av-profile:
                        type: str
                        description: no description
                    deep-inspection-options:
                        type: str
                        description: no description
                    devices:
                        type: str
                        description: no description
                    dlp-sensor:
                        type: str
                        description: no description
                    endpoint-compliance:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: no description
                    icap-profile:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    ips-sensor:
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
                    mms-profile:
                        type: str
                        description: no description
                    per-ip-shaper:
                        type: str
                        description: no description
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
                    replacemsg-group:
                        type: str
                        description: no description
                    schedule:
                        type: str
                        description: no description
                    send-deny-packet:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    service:
                        type: str
                        description: no description
                    service-negate:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    spamfilter-profile:
                        type: str
                        description: no description
                    sslvpn-portal:
                        type: str
                        description: no description
                    sslvpn-realm:
                        type: str
                        description: no description
                    traffic-shaper:
                        type: str
                        description: no description
                    traffic-shaper-reverse:
                        type: str
                        description: no description
                    utm-status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    voip-profile:
                        type: str
                        description: no description
                    webfilter-profile:
                        type: str
                        description: no description
            identity-from:
                type: str
                description: no description
                choices:
                    - 'auth'
                    - 'device'
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
            mms-profile:
                type: str
                description: no description
            name:
                type: str
                description: no description
            nat:
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
            natoutbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            np-accelation:
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
            outbound:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: no description
            policyid:
                type: int
                description: no description
            poolname:
                type: str
                description: no description
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
            replacemsg-group:
                type: str
                description: no description
            replacemsg-override-group:
                type: str
                description: no description
            rsso:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            schedule:
                type: str
                description: no description
            send-deny-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: str
                description: no description
            service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            session-ttl:
                type: int
                description: no description
            spamfilter-profile:
                type: str
                description: no description
            srcaddr:
                type: str
                description: no description
            srcaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: str
                description: no description
            ssh-filter-profile:
                type: str
                description: no description
            ssh-policy-redirect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror-intf:
                type: str
                description: no description
            ssl-ssh-profile:
                type: str
                description: no description
            sslvpn-auth:
                type: str
                description: no description
                choices:
                    - 'any'
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs+'
            sslvpn-ccert:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-cipher:
                type: str
                description: no description
                choices:
                    - 'any'
                    - 'high'
                    - 'medium'
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: no description
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
            url-category:
                type: str
                description: no description
            users:
                type: str
                description: no description
            utm-inspection-mode:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow'
            utm-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
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
            webfilter-profile:
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
      fmgr_pkg_header_policy6:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         pkg: <your own value>
         state: <value in [present, absent]>
         pkg_header_policy6:
            action: <value in [deny, accept, ipsec, ...]>
            anti-replay: <value in [disable, enable]>
            app-category: <value of string>
            app-group: <value of string>
            application: <value of integer>
            application-charts:
              - top10-app
              - top10-p2p-user
              - top10-media-user
            application-list: <value of string>
            auto-asic-offload: <value in [disable, enable]>
            av-profile: <value of string>
            casi-profile: <value of string>
            cifs-profile: <value of string>
            comments: <value of string>
            custom-log-fields: <value of string>
            deep-inspection-options: <value of string>
            device-detection-portal: <value in [disable, enable]>
            devices: <value of string>
            diffserv-forward: <value in [disable, enable]>
            diffserv-reverse: <value in [disable, enable]>
            diffservcode-forward: <value of string>
            diffservcode-rev: <value of string>
            dlp-sensor: <value of string>
            dnsfilter-profile: <value of string>
            dscp-match: <value in [disable, enable]>
            dscp-negate: <value in [disable, enable]>
            dscp-value: <value of string>
            dsri: <value in [disable, enable]>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            dstintf: <value of string>
            dynamic-profile: <value in [disable, enable]>
            dynamic-profile-access:
              - imap
              - smtp
              - pop3
              - http
              - ftp
              - im
              - nntp
              - imaps
              - smtps
              - pop3s
              - https
              - ftps
            dynamic-profile-group: <value of string>
            email-collection-portal: <value in [disable, enable]>
            emailfilter-profile: <value of string>
            firewall-session-dirty: <value in [check-all, check-new]>
            fixedport: <value in [disable, enable]>
            fsae: <value in [disable, enable]>
            global-label: <value of string>
            groups: <value of string>
            http-policy-redirect: <value in [disable, enable]>
            icap-profile: <value of string>
            identity-based: <value in [disable, enable]>
            identity-based-policy6:
              -
                  action: <value in [deny, accept]>
                  application-list: <value of string>
                  av-profile: <value of string>
                  deep-inspection-options: <value of string>
                  devices: <value of string>
                  dlp-sensor: <value of string>
                  endpoint-compliance: <value in [disable, enable]>
                  groups: <value of string>
                  icap-profile: <value of string>
                  id: <value of integer>
                  ips-sensor: <value of string>
                  logtraffic: <value in [disable, enable, all, ...]>
                  mms-profile: <value of string>
                  per-ip-shaper: <value of string>
                  profile-group: <value of string>
                  profile-protocol-options: <value of string>
                  profile-type: <value in [single, group]>
                  replacemsg-group: <value of string>
                  schedule: <value of string>
                  send-deny-packet: <value in [disable, enable]>
                  service: <value of string>
                  service-negate: <value in [disable, enable]>
                  spamfilter-profile: <value of string>
                  sslvpn-portal: <value of string>
                  sslvpn-realm: <value of string>
                  traffic-shaper: <value of string>
                  traffic-shaper-reverse: <value of string>
                  utm-status: <value in [disable, enable]>
                  voip-profile: <value of string>
                  webfilter-profile: <value of string>
            identity-from: <value in [auth, device]>
            inbound: <value in [disable, enable]>
            inspection-mode: <value in [proxy, flow]>
            ippool: <value in [disable, enable]>
            ips-sensor: <value of string>
            label: <value of string>
            logtraffic: <value in [disable, enable, all, ...]>
            logtraffic-start: <value in [disable, enable]>
            mms-profile: <value of string>
            name: <value of string>
            nat: <value in [disable, enable]>
            natinbound: <value in [disable, enable]>
            natoutbound: <value in [disable, enable]>
            np-accelation: <value in [disable, enable]>
            np-acceleration: <value in [disable, enable]>
            outbound: <value in [disable, enable]>
            per-ip-shaper: <value of string>
            policyid: <value of integer>
            poolname: <value of string>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            replacemsg-group: <value of string>
            replacemsg-override-group: <value of string>
            rsso: <value in [disable, enable]>
            schedule: <value of string>
            send-deny-packet: <value in [disable, enable]>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            session-ttl: <value of integer>
            spamfilter-profile: <value of string>
            srcaddr: <value of string>
            srcaddr-negate: <value in [disable, enable]>
            srcintf: <value of string>
            ssh-filter-profile: <value of string>
            ssh-policy-redirect: <value in [disable, enable]>
            ssl-mirror: <value in [disable, enable]>
            ssl-mirror-intf: <value of string>
            ssl-ssh-profile: <value of string>
            sslvpn-auth: <value in [any, local, radius, ...]>
            sslvpn-ccert: <value in [disable, enable]>
            sslvpn-cipher: <value in [any, high, medium]>
            status: <value in [disable, enable]>
            tags: <value of string>
            tcp-mss-receiver: <value of integer>
            tcp-mss-sender: <value of integer>
            tcp-session-without-syn: <value in [all, data-only, disable]>
            timeout-send-rst: <value in [disable, enable]>
            tos: <value of string>
            tos-mask: <value of string>
            tos-negate: <value in [disable, enable]>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            url-category: <value of string>
            users: <value of string>
            utm-inspection-mode: <value in [proxy, flow]>
            utm-status: <value in [disable, enable]>
            uuid: <value of string>
            vlan-cos-fwd: <value of integer>
            vlan-cos-rev: <value of integer>
            vlan-filter: <value of string>
            voip-profile: <value of string>
            vpntunnel: <value of string>
            webfilter-profile: <value of string>

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
        '/pm/config/global/pkg/{pkg}/global/header/policy6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}'
    ]

    url_params = ['pkg']
    module_primary_key = 'policyid'
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_header_policy6': {
            'required': False,
            'type': 'dict',
            'options': {
                'action': {
                    'required': False,
                    'choices': [
                        'deny',
                        'accept',
                        'ipsec',
                        'ssl-vpn'
                    ],
                    'type': 'str'
                },
                'anti-replay': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'app-category': {
                    'required': False,
                    'type': 'str'
                },
                'app-group': {
                    'required': False,
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'type': 'int'
                },
                'application-charts': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'top10-app',
                        'top10-p2p-user',
                        'top10-media-user'
                    ]
                },
                'application-list': {
                    'required': False,
                    'type': 'str'
                },
                'auto-asic-offload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'type': 'str'
                },
                'casi-profile': {
                    'required': False,
                    'type': 'str'
                },
                'cifs-profile': {
                    'required': False,
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'type': 'str'
                },
                'custom-log-fields': {
                    'required': False,
                    'type': 'str'
                },
                'deep-inspection-options': {
                    'required': False,
                    'type': 'str'
                },
                'device-detection-portal': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'devices': {
                    'required': False,
                    'type': 'str'
                },
                'diffserv-forward': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'diffserv-reverse': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'diffservcode-forward': {
                    'required': False,
                    'type': 'str'
                },
                'diffservcode-rev': {
                    'required': False,
                    'type': 'str'
                },
                'dlp-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'dnsfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'dscp-match': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dscp-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dscp-value': {
                    'required': False,
                    'type': 'str'
                },
                'dsri': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'type': 'str'
                },
                'dynamic-profile': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dynamic-profile-access': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'imap',
                        'smtp',
                        'pop3',
                        'http',
                        'ftp',
                        'im',
                        'nntp',
                        'imaps',
                        'smtps',
                        'pop3s',
                        'https',
                        'ftps'
                    ]
                },
                'dynamic-profile-group': {
                    'required': False,
                    'type': 'str'
                },
                'email-collection-portal': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'emailfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'firewall-session-dirty': {
                    'required': False,
                    'choices': [
                        'check-all',
                        'check-new'
                    ],
                    'type': 'str'
                },
                'fixedport': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fsae': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'global-label': {
                    'required': False,
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'type': 'str'
                },
                'http-policy-redirect': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'icap-profile': {
                    'required': False,
                    'type': 'str'
                },
                'identity-based': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'identity-based-policy6': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'deny',
                                'accept'
                            ],
                            'type': 'str'
                        },
                        'application-list': {
                            'required': False,
                            'type': 'str'
                        },
                        'av-profile': {
                            'required': False,
                            'type': 'str'
                        },
                        'deep-inspection-options': {
                            'required': False,
                            'type': 'str'
                        },
                        'devices': {
                            'required': False,
                            'type': 'str'
                        },
                        'dlp-sensor': {
                            'required': False,
                            'type': 'str'
                        },
                        'endpoint-compliance': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'groups': {
                            'required': False,
                            'type': 'str'
                        },
                        'icap-profile': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'ips-sensor': {
                            'required': False,
                            'type': 'str'
                        },
                        'logtraffic': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable',
                                'all',
                                'utm'
                            ],
                            'type': 'str'
                        },
                        'mms-profile': {
                            'required': False,
                            'type': 'str'
                        },
                        'per-ip-shaper': {
                            'required': False,
                            'type': 'str'
                        },
                        'profile-group': {
                            'required': False,
                            'type': 'str'
                        },
                        'profile-protocol-options': {
                            'required': False,
                            'type': 'str'
                        },
                        'profile-type': {
                            'required': False,
                            'choices': [
                                'single',
                                'group'
                            ],
                            'type': 'str'
                        },
                        'replacemsg-group': {
                            'required': False,
                            'type': 'str'
                        },
                        'schedule': {
                            'required': False,
                            'type': 'str'
                        },
                        'send-deny-packet': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'service': {
                            'required': False,
                            'type': 'str'
                        },
                        'service-negate': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'spamfilter-profile': {
                            'required': False,
                            'type': 'str'
                        },
                        'sslvpn-portal': {
                            'required': False,
                            'type': 'str'
                        },
                        'sslvpn-realm': {
                            'required': False,
                            'type': 'str'
                        },
                        'traffic-shaper': {
                            'required': False,
                            'type': 'str'
                        },
                        'traffic-shaper-reverse': {
                            'required': False,
                            'type': 'str'
                        },
                        'utm-status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'voip-profile': {
                            'required': False,
                            'type': 'str'
                        },
                        'webfilter-profile': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'identity-from': {
                    'required': False,
                    'choices': [
                        'auth',
                        'device'
                    ],
                    'type': 'str'
                },
                'inbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'inspection-mode': {
                    'required': False,
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'ippool': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ips-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'label': {
                    'required': False,
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
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
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-profile': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'nat': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'natinbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'natoutbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'np-accelation': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'np-acceleration': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'outbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'policyid': {
                    'required': True,
                    'type': 'int'
                },
                'poolname': {
                    'required': False,
                    'type': 'str'
                },
                'profile-group': {
                    'required': False,
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'type': 'str'
                },
                'replacemsg-override-group': {
                    'required': False,
                    'type': 'str'
                },
                'rsso': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'type': 'str'
                },
                'send-deny-packet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'type': 'str'
                },
                'service-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'session-ttl': {
                    'required': False,
                    'type': 'int'
                },
                'spamfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcintf': {
                    'required': False,
                    'type': 'str'
                },
                'ssh-filter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'ssh-policy-redirect': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-mirror': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-mirror-intf': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-ssh-profile': {
                    'required': False,
                    'type': 'str'
                },
                'sslvpn-auth': {
                    'required': False,
                    'choices': [
                        'any',
                        'local',
                        'radius',
                        'ldap',
                        'tacacs+'
                    ],
                    'type': 'str'
                },
                'sslvpn-ccert': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-cipher': {
                    'required': False,
                    'choices': [
                        'any',
                        'high',
                        'medium'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tags': {
                    'required': False,
                    'type': 'str'
                },
                'tcp-mss-receiver': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-mss-sender': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-session-without-syn': {
                    'required': False,
                    'choices': [
                        'all',
                        'data-only',
                        'disable'
                    ],
                    'type': 'str'
                },
                'timeout-send-rst': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tos': {
                    'required': False,
                    'type': 'str'
                },
                'tos-mask': {
                    'required': False,
                    'type': 'str'
                },
                'tos-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'traffic-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'traffic-shaper-reverse': {
                    'required': False,
                    'type': 'str'
                },
                'url-category': {
                    'required': False,
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'type': 'str'
                },
                'utm-inspection-mode': {
                    'required': False,
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'utm-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'vlan-cos-fwd': {
                    'required': False,
                    'type': 'int'
                },
                'vlan-cos-rev': {
                    'required': False,
                    'type': 'int'
                },
                'vlan-filter': {
                    'required': False,
                    'type': 'str'
                },
                'voip-profile': {
                    'required': False,
                    'type': 'str'
                },
                'vpntunnel': {
                    'required': False,
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = [
        {
            'attribute_path': [
                'pkg_header_policy6',
                'policyid'
            ],
            'lambda': 'int($) >= 1073741824',
            'fail_action': 'warn',
            'hint_message': 'policyid should be larger than 2^30, i.e. 1073741824, otherwise it will be ignored.'
        }
    ]

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_header_policy6'),
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
