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
module: fmgr_firewall_gtp
short_description: Configure GTP.
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
    firewall_gtp:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            addr-notify:
                type: str
                description: 'overbilling notify address'
            apn:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        type: str
                        description: 'APN member.'
                    id:
                        type: int
                        description: 'ID.'
                    selection-mode:
                        description: no description
                        type: list
                        choices:
                         - ms
                         - net
                         - vrf
            apn-filter:
                type: str
                description: 'apn filter'
                choices:
                    - 'disable'
                    - 'enable'
            authorized-ggsns:
                type: str
                description: 'Authorized GGSN group'
            authorized-sgsns:
                type: str
                description: 'Authorized SGSN group'
            comment:
                type: str
                description: 'Comment.'
            context-id:
                type: int
                description: 'Overbilling context.'
            control-plane-message-rate-limit:
                type: int
                description: 'control plane message rate limit'
            default-apn-action:
                type: str
                description: 'default apn action'
                choices:
                    - 'allow'
                    - 'deny'
            default-imsi-action:
                type: str
                description: 'default imsi action'
                choices:
                    - 'allow'
                    - 'deny'
            default-ip-action:
                type: str
                description: 'default action for encapsulated IP traffic'
                choices:
                    - 'allow'
                    - 'deny'
            default-noip-action:
                type: str
                description: 'default action for encapsulated non-IP traffic'
                choices:
                    - 'allow'
                    - 'deny'
            default-policy-action:
                type: str
                description: 'default advanced policy action'
                choices:
                    - 'allow'
                    - 'deny'
            denied-log:
                type: str
                description: 'log denied'
                choices:
                    - 'disable'
                    - 'enable'
            echo-request-interval:
                type: int
                description: 'echo request interval (in seconds)'
            extension-log:
                type: str
                description: 'log in extension format'
                choices:
                    - 'disable'
                    - 'enable'
            forwarded-log:
                type: str
                description: 'log forwarded'
                choices:
                    - 'disable'
                    - 'enable'
            global-tunnel-limit:
                type: str
                description: 'Global tunnel limit.'
            gtp-in-gtp:
                type: str
                description: 'gtp in gtp'
                choices:
                    - 'allow'
                    - 'deny'
            gtpu-denied-log:
                type: str
                description: 'Enable/disable logging of denied GTP-U packets.'
                choices:
                    - 'disable'
                    - 'enable'
            gtpu-forwarded-log:
                type: str
                description: 'Enable/disable logging of forwarded GTP-U packets.'
                choices:
                    - 'disable'
                    - 'enable'
            gtpu-log-freq:
                type: int
                description: 'Logging of frequency of GTP-U packets.'
            half-close-timeout:
                type: int
                description: 'Half-close tunnel timeout (in seconds).'
            half-open-timeout:
                type: int
                description: 'Half-open tunnel timeout (in seconds).'
            handover-group:
                type: str
                description: 'Handover SGSN group'
            ie-remove-policy:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: 'ID.'
                    remove-ies:
                        description: no description
                        type: list
                        choices:
                         - apn-restriction
                         - rat-type
                         - rai
                         - uli
                         - imei
                    sgsn-addr:
                        type: str
                        description: 'SGSN address name.'
            ie-remover:
                type: str
                description: 'IE removal policy.'
                choices:
                    - 'disable'
                    - 'enable'
            ie-white-list-v0v1:
                type: str
                description: 'IE white list.'
            ie-white-list-v2:
                type: str
                description: 'IE white list.'
            imsi:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        type: str
                        description: 'APN member.'
                    id:
                        type: int
                        description: 'ID.'
                    mcc-mnc:
                        type: str
                        description: 'MCC MNC.'
                    msisdn-prefix:
                        type: str
                        description: 'MSISDN prefix.'
                    selection-mode:
                        description: no description
                        type: list
                        choices:
                         - ms
                         - net
                         - vrf
            imsi-filter:
                type: str
                description: 'imsi filter'
                choices:
                    - 'disable'
                    - 'enable'
            interface-notify:
                type: str
                description: 'overbilling interface'
            invalid-reserved-field:
                type: str
                description: 'Invalid reserved field in GTP header'
                choices:
                    - 'allow'
                    - 'deny'
            invalid-sgsns-to-log:
                type: str
                description: 'Invalid SGSN group to be logged'
            ip-filter:
                type: str
                description: 'IP filter for encapsulted traffic'
                choices:
                    - 'disable'
                    - 'enable'
            ip-policy:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'deny'
                    dstaddr:
                        type: str
                        description: 'Destination address name.'
                    id:
                        type: int
                        description: 'ID.'
                    srcaddr:
                        type: str
                        description: 'Source address name.'
            log-freq:
                type: int
                description: 'Logging of frequency of GTP-C packets.'
            log-gtpu-limit:
                type: int
                description: 'the user data log limit (0-512 bytes)'
            log-imsi-prefix:
                type: str
                description: 'IMSI prefix for selective logging.'
            log-msisdn-prefix:
                type: str
                description: 'the msisdn prefix for selective logging'
            max-message-length:
                type: int
                description: 'max message length'
            message-filter-v0v1:
                type: str
                description: 'Message filter.'
            message-filter-v2:
                type: str
                description: 'Message filter.'
            min-message-length:
                type: int
                description: 'min message length'
            miss-must-ie:
                type: str
                description: 'Missing mandatory information element'
                choices:
                    - 'allow'
                    - 'deny'
            monitor-mode:
                type: str
                description: 'GTP monitor mode'
                choices:
                    - 'disable'
                    - 'enable'
                    - 'vdom'
            name:
                type: str
                description: 'Profile name.'
            noip-filter:
                type: str
                description: 'non-IP filter for encapsulted traffic'
                choices:
                    - 'disable'
                    - 'enable'
            noip-policy:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'deny'
                    end:
                        type: int
                        description: 'End of protocol range (0 - 255).'
                    id:
                        type: int
                        description: 'ID.'
                    start:
                        type: int
                        description: 'Start of protocol range (0 - 255).'
                    type:
                        type: str
                        description: 'Protocol field type.'
                        choices:
                            - 'etsi'
                            - 'ietf'
            out-of-state-ie:
                type: str
                description: 'Out of state information element.'
                choices:
                    - 'allow'
                    - 'deny'
            out-of-state-message:
                type: str
                description: 'Out of state GTP message'
                choices:
                    - 'allow'
                    - 'deny'
            per-apn-shaper:
                description: no description
                type: list
                suboptions:
                    apn:
                        type: str
                        description: 'APN name.'
                    id:
                        type: int
                        description: 'ID.'
                    rate-limit:
                        type: int
                        description: 'Rate limit (packets/s) for create PDP context request.'
                    version:
                        type: int
                        description: 'GTP version number: 0 or 1.'
            policy:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'allow'
                            - 'deny'
                    apn-sel-mode:
                        description: no description
                        type: list
                        choices:
                         - ms
                         - net
                         - vrf
                    apnmember:
                        type: str
                        description: 'APN member.'
                    id:
                        type: int
                        description: 'ID.'
                    imei:
                        type: str
                        description: 'IMEI(SV) pattern.'
                    imsi:
                        type: str
                        description: 'IMSI prefix.'
                    max-apn-restriction:
                        type: str
                        description: 'Maximum APN restriction value.'
                        choices:
                            - 'all'
                            - 'public-1'
                            - 'public-2'
                            - 'private-1'
                            - 'private-2'
                    messages:
                        description: no description
                        type: list
                        choices:
                         - create-req
                         - create-res
                         - update-req
                         - update-res
                    msisdn:
                        type: str
                        description: 'MSISDN prefix.'
                    rai:
                        type: str
                        description: 'RAI pattern.'
                    rat-type:
                        description: no description
                        type: list
                        choices:
                         - any
                         - utran
                         - geran
                         - wlan
                         - gan
                         - hspa
                         - eutran
                         - virtual
                         - nbiot
                    uli:
                        type: str
                        description: 'ULI pattern.'
            policy-filter:
                type: str
                description: 'Advanced policy filter'
                choices:
                    - 'disable'
                    - 'enable'
            port-notify:
                type: int
                description: 'overbilling notify port'
            rate-limit-mode:
                type: str
                description: 'GTP rate limit mode.'
                choices:
                    - 'per-profile'
                    - 'per-stream'
                    - 'per-apn'
            rate-limited-log:
                type: str
                description: 'log rate limited'
                choices:
                    - 'disable'
                    - 'enable'
            rate-sampling-interval:
                type: int
                description: 'rate sampling interval (1-3600 seconds)'
            remove-if-echo-expires:
                type: str
                description: 'remove if echo response expires'
                choices:
                    - 'disable'
                    - 'enable'
            remove-if-recovery-differ:
                type: str
                description: 'remove upon different Recovery IE'
                choices:
                    - 'disable'
                    - 'enable'
            reserved-ie:
                type: str
                description: 'reserved information element'
                choices:
                    - 'allow'
                    - 'deny'
            send-delete-when-timeout:
                type: str
                description: 'send DELETE request to path endpoints when GTPv0/v1 tunnel timeout.'
                choices:
                    - 'disable'
                    - 'enable'
            send-delete-when-timeout-v2:
                type: str
                description: 'send DELETE request to path endpoints when GTPv2 tunnel timeout.'
                choices:
                    - 'disable'
                    - 'enable'
            spoof-src-addr:
                type: str
                description: 'Spoofed source address for Mobile Station.'
                choices:
                    - 'allow'
                    - 'deny'
            state-invalid-log:
                type: str
                description: 'log state invalid'
                choices:
                    - 'disable'
                    - 'enable'
            traffic-count-log:
                type: str
                description: 'log tunnel traffic counter'
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-limit:
                type: int
                description: 'tunnel limit'
            tunnel-limit-log:
                type: str
                description: 'tunnel limit'
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-timeout:
                type: int
                description: 'Established tunnel timeout (in seconds).'
            unknown-version-action:
                type: str
                description: 'action for unknown gtp version'
                choices:
                    - 'allow'
                    - 'deny'
            user-plane-message-rate-limit:
                type: int
                description: 'user plane message rate limit'
            warning-threshold:
                type: int
                description: 'Warning threshold for rate limiting (0 - 99 percent).'

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
    - name: Configure GTP.
      fmgr_firewall_gtp:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_gtp:
            addr-notify: <value of string>
            apn:
              -
                  action: <value in [allow, deny]>
                  apnmember: <value of string>
                  id: <value of integer>
                  selection-mode:
                    - ms
                    - net
                    - vrf
            apn-filter: <value in [disable, enable]>
            authorized-ggsns: <value of string>
            authorized-sgsns: <value of string>
            comment: <value of string>
            context-id: <value of integer>
            control-plane-message-rate-limit: <value of integer>
            default-apn-action: <value in [allow, deny]>
            default-imsi-action: <value in [allow, deny]>
            default-ip-action: <value in [allow, deny]>
            default-noip-action: <value in [allow, deny]>
            default-policy-action: <value in [allow, deny]>
            denied-log: <value in [disable, enable]>
            echo-request-interval: <value of integer>
            extension-log: <value in [disable, enable]>
            forwarded-log: <value in [disable, enable]>
            global-tunnel-limit: <value of string>
            gtp-in-gtp: <value in [allow, deny]>
            gtpu-denied-log: <value in [disable, enable]>
            gtpu-forwarded-log: <value in [disable, enable]>
            gtpu-log-freq: <value of integer>
            half-close-timeout: <value of integer>
            half-open-timeout: <value of integer>
            handover-group: <value of string>
            ie-remove-policy:
              -
                  id: <value of integer>
                  remove-ies:
                    - apn-restriction
                    - rat-type
                    - rai
                    - uli
                    - imei
                  sgsn-addr: <value of string>
            ie-remover: <value in [disable, enable]>
            ie-white-list-v0v1: <value of string>
            ie-white-list-v2: <value of string>
            imsi:
              -
                  action: <value in [allow, deny]>
                  apnmember: <value of string>
                  id: <value of integer>
                  mcc-mnc: <value of string>
                  msisdn-prefix: <value of string>
                  selection-mode:
                    - ms
                    - net
                    - vrf
            imsi-filter: <value in [disable, enable]>
            interface-notify: <value of string>
            invalid-reserved-field: <value in [allow, deny]>
            invalid-sgsns-to-log: <value of string>
            ip-filter: <value in [disable, enable]>
            ip-policy:
              -
                  action: <value in [allow, deny]>
                  dstaddr: <value of string>
                  id: <value of integer>
                  srcaddr: <value of string>
            log-freq: <value of integer>
            log-gtpu-limit: <value of integer>
            log-imsi-prefix: <value of string>
            log-msisdn-prefix: <value of string>
            max-message-length: <value of integer>
            message-filter-v0v1: <value of string>
            message-filter-v2: <value of string>
            min-message-length: <value of integer>
            miss-must-ie: <value in [allow, deny]>
            monitor-mode: <value in [disable, enable, vdom]>
            name: <value of string>
            noip-filter: <value in [disable, enable]>
            noip-policy:
              -
                  action: <value in [allow, deny]>
                  end: <value of integer>
                  id: <value of integer>
                  start: <value of integer>
                  type: <value in [etsi, ietf]>
            out-of-state-ie: <value in [allow, deny]>
            out-of-state-message: <value in [allow, deny]>
            per-apn-shaper:
              -
                  apn: <value of string>
                  id: <value of integer>
                  rate-limit: <value of integer>
                  version: <value of integer>
            policy:
              -
                  action: <value in [allow, deny]>
                  apn-sel-mode:
                    - ms
                    - net
                    - vrf
                  apnmember: <value of string>
                  id: <value of integer>
                  imei: <value of string>
                  imsi: <value of string>
                  max-apn-restriction: <value in [all, public-1, public-2, ...]>
                  messages:
                    - create-req
                    - create-res
                    - update-req
                    - update-res
                  msisdn: <value of string>
                  rai: <value of string>
                  rat-type:
                    - any
                    - utran
                    - geran
                    - wlan
                    - gan
                    - hspa
                    - eutran
                    - virtual
                    - nbiot
                  uli: <value of string>
            policy-filter: <value in [disable, enable]>
            port-notify: <value of integer>
            rate-limit-mode: <value in [per-profile, per-stream, per-apn]>
            rate-limited-log: <value in [disable, enable]>
            rate-sampling-interval: <value of integer>
            remove-if-echo-expires: <value in [disable, enable]>
            remove-if-recovery-differ: <value in [disable, enable]>
            reserved-ie: <value in [allow, deny]>
            send-delete-when-timeout: <value in [disable, enable]>
            send-delete-when-timeout-v2: <value in [disable, enable]>
            spoof-src-addr: <value in [allow, deny]>
            state-invalid-log: <value in [disable, enable]>
            traffic-count-log: <value in [disable, enable]>
            tunnel-limit: <value of integer>
            tunnel-limit-log: <value in [disable, enable]>
            tunnel-timeout: <value of integer>
            unknown-version-action: <value in [allow, deny]>
            user-plane-message-rate-limit: <value of integer>
            warning-threshold: <value of integer>

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
        '/pm/config/adom/{adom}/obj/firewall/gtp',
        '/pm/config/global/obj/firewall/gtp'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
        '/pm/config/global/obj/firewall/gtp/{gtp}'
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
        'firewall_gtp': {
            'required': False,
            'type': 'dict',
            'options': {
                'addr-notify': {
                    'required': False,
                    'type': 'str'
                },
                'apn': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apnmember': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'selection-mode': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'ms',
                                'net',
                                'vrf'
                            ]
                        }
                    }
                },
                'apn-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'authorized-ggsns': {
                    'required': False,
                    'type': 'str'
                },
                'authorized-sgsns': {
                    'required': False,
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'context-id': {
                    'required': False,
                    'type': 'int'
                },
                'control-plane-message-rate-limit': {
                    'required': False,
                    'type': 'int'
                },
                'default-apn-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-imsi-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-ip-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-noip-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-policy-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'denied-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'echo-request-interval': {
                    'required': False,
                    'type': 'int'
                },
                'extension-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'forwarded-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'global-tunnel-limit': {
                    'required': False,
                    'type': 'str'
                },
                'gtp-in-gtp': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'gtpu-denied-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gtpu-forwarded-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gtpu-log-freq': {
                    'required': False,
                    'type': 'int'
                },
                'half-close-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'half-open-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'handover-group': {
                    'required': False,
                    'type': 'str'
                },
                'ie-remove-policy': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'remove-ies': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'apn-restriction',
                                'rat-type',
                                'rai',
                                'uli',
                                'imei'
                            ]
                        },
                        'sgsn-addr': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'ie-remover': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ie-white-list-v0v1': {
                    'required': False,
                    'type': 'str'
                },
                'ie-white-list-v2': {
                    'required': False,
                    'type': 'str'
                },
                'imsi': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apnmember': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'mcc-mnc': {
                            'required': False,
                            'type': 'str'
                        },
                        'msisdn-prefix': {
                            'required': False,
                            'type': 'str'
                        },
                        'selection-mode': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'ms',
                                'net',
                                'vrf'
                            ]
                        }
                    }
                },
                'imsi-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'interface-notify': {
                    'required': False,
                    'type': 'str'
                },
                'invalid-reserved-field': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'invalid-sgsns-to-log': {
                    'required': False,
                    'type': 'str'
                },
                'ip-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip-policy': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'dstaddr': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'srcaddr': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'log-freq': {
                    'required': False,
                    'type': 'int'
                },
                'log-gtpu-limit': {
                    'required': False,
                    'type': 'int'
                },
                'log-imsi-prefix': {
                    'required': False,
                    'type': 'str'
                },
                'log-msisdn-prefix': {
                    'required': False,
                    'type': 'str'
                },
                'max-message-length': {
                    'required': False,
                    'type': 'int'
                },
                'message-filter-v0v1': {
                    'required': False,
                    'type': 'str'
                },
                'message-filter-v2': {
                    'required': False,
                    'type': 'str'
                },
                'min-message-length': {
                    'required': False,
                    'type': 'int'
                },
                'miss-must-ie': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'monitor-mode': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'vdom'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'noip-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'noip-policy': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'end': {
                            'required': False,
                            'type': 'int'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'start': {
                            'required': False,
                            'type': 'int'
                        },
                        'type': {
                            'required': False,
                            'choices': [
                                'etsi',
                                'ietf'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'out-of-state-ie': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'out-of-state-message': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'per-apn-shaper': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'apn': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'rate-limit': {
                            'required': False,
                            'type': 'int'
                        },
                        'version': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'policy': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apn-sel-mode': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'ms',
                                'net',
                                'vrf'
                            ]
                        },
                        'apnmember': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'imei': {
                            'required': False,
                            'type': 'str'
                        },
                        'imsi': {
                            'required': False,
                            'type': 'str'
                        },
                        'max-apn-restriction': {
                            'required': False,
                            'choices': [
                                'all',
                                'public-1',
                                'public-2',
                                'private-1',
                                'private-2'
                            ],
                            'type': 'str'
                        },
                        'messages': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'create-req',
                                'create-res',
                                'update-req',
                                'update-res'
                            ]
                        },
                        'msisdn': {
                            'required': False,
                            'type': 'str'
                        },
                        'rai': {
                            'required': False,
                            'type': 'str'
                        },
                        'rat-type': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'any',
                                'utran',
                                'geran',
                                'wlan',
                                'gan',
                                'hspa',
                                'eutran',
                                'virtual',
                                'nbiot'
                            ]
                        },
                        'uli': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'policy-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'port-notify': {
                    'required': False,
                    'type': 'int'
                },
                'rate-limit-mode': {
                    'required': False,
                    'choices': [
                        'per-profile',
                        'per-stream',
                        'per-apn'
                    ],
                    'type': 'str'
                },
                'rate-limited-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-sampling-interval': {
                    'required': False,
                    'type': 'int'
                },
                'remove-if-echo-expires': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'remove-if-recovery-differ': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'reserved-ie': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'send-delete-when-timeout': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'send-delete-when-timeout-v2': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spoof-src-addr': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'state-invalid-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'traffic-count-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-limit': {
                    'required': False,
                    'type': 'int'
                },
                'tunnel-limit-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'unknown-version-action': {
                    'required': False,
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'user-plane-message-rate-limit': {
                    'required': False,
                    'type': 'int'
                },
                'warning-threshold': {
                    'required': False,
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp'),
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
