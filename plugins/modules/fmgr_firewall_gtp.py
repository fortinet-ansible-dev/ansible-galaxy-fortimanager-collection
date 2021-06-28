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
                    sgsn-addr6:
                        type: str
                        description: 'SGSN IPv6 address name.'
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
                    dstaddr6:
                        type: str
                        description: 'Destination IPv6 address name.'
                    srcaddr6:
                        type: str
                        description: 'Source IPv6 address name.'
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
                    imsi-prefix:
                        type: str
                        description: 'IMSI prefix.'
                    msisdn-prefix:
                        type: str
                        description: 'MSISDN prefix.'
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
            policy-v2:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action.'
                        choices:
                            - 'deny'
                            - 'allow'
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
                    imsi-prefix:
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
                    mei:
                        type: str
                        description: 'MEI pattern.'
                    messages:
                        description: no description
                        type: list
                        choices:
                         - create-ses-req
                         - create-ses-res
                         - modify-bearer-req
                         - modify-bearer-res
                    msisdn-prefix:
                        type: str
                        description: 'MSISDN prefix.'
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
                         - ltem
                         - nr
                    uli:
                        description: no description
                        type: str
            sub-second-interval:
                type: str
                description: 'Sub-second interval (0.1, 0.25, or 0.5 sec, default = 0.5).'
                choices:
                    - '0.1'
                    - '0.25'
                    - '0.5'
            sub-second-sampling:
                type: str
                description: 'Enable/disable sub-second sampling.'
                choices:
                    - 'disable'
                    - 'enable'
            authorized-ggsns6:
                type: str
                description: 'Authorized GGSN/PGW IPv6 group.'
            authorized-sgsns6:
                type: str
                description: 'Authorized SGSN/SGW IPv6 group.'
            handover-group6:
                type: str
                description: 'Handover SGSN/SGW IPv6 group.'
            invalid-sgsns6-to-log:
                type: str
                description: 'Invalid SGSN IPv6 group to be logged.'
            ie-validation:
                description: no description
                type: dict
                required: false
                suboptions:
                    apn-restriction:
                        type: str
                        description: 'Validate APN restriction.'
                        choices:
                            - 'disable'
                            - 'enable'
                    charging-ID:
                        type: str
                        description: 'Validate charging ID.'
                        choices:
                            - 'disable'
                            - 'enable'
                    charging-gateway-addr:
                        type: str
                        description: 'Validate charging gateway address.'
                        choices:
                            - 'disable'
                            - 'enable'
                    end-user-addr:
                        type: str
                        description: 'Validate end user address.'
                        choices:
                            - 'disable'
                            - 'enable'
                    gsn-addr:
                        type: str
                        description: 'Validate GSN address.'
                        choices:
                            - 'disable'
                            - 'enable'
                    imei:
                        type: str
                        description: 'Validate IMEI(SV).'
                        choices:
                            - 'disable'
                            - 'enable'
                    imsi:
                        type: str
                        description: 'Validate IMSI.'
                        choices:
                            - 'disable'
                            - 'enable'
                    mm-context:
                        type: str
                        description: 'Validate MM context.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ms-tzone:
                        type: str
                        description: 'Validate MS time zone.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ms-validated:
                        type: str
                        description: 'Validate MS validated.'
                        choices:
                            - 'disable'
                            - 'enable'
                    msisdn:
                        type: str
                        description: 'Validate MSISDN.'
                        choices:
                            - 'disable'
                            - 'enable'
                    nsapi:
                        type: str
                        description: 'Validate NSAPI.'
                        choices:
                            - 'disable'
                            - 'enable'
                    pdp-context:
                        type: str
                        description: 'Validate PDP context.'
                        choices:
                            - 'disable'
                            - 'enable'
                    qos-profile:
                        type: str
                        description: 'Validate Quality of Service(QoS) profile.'
                        choices:
                            - 'disable'
                            - 'enable'
                    rai:
                        type: str
                        description: 'Validate RAI.'
                        choices:
                            - 'disable'
                            - 'enable'
                    rat-type:
                        type: str
                        description: 'Validate RAT type.'
                        choices:
                            - 'disable'
                            - 'enable'
                    reordering-required:
                        type: str
                        description: 'Validate re-ordering required.'
                        choices:
                            - 'disable'
                            - 'enable'
                    selection-mode:
                        type: str
                        description: 'Validate selection mode.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uli:
                        type: str
                        description: 'Validate user location information.'
                        choices:
                            - 'disable'
                            - 'enable'
            message-rate-limit:
                description: no description
                type: dict
                required: false
                suboptions:
                    create-aa-pdp-request:
                        type: int
                        description: 'Rate limit for create AA PDP context request (packets per second).'
                    create-aa-pdp-response:
                        type: int
                        description: 'Rate limit for create AA PDP context response (packets per second).'
                    create-mbms-request:
                        type: int
                        description: 'Rate limit for create MBMS context request (packets per second).'
                    create-mbms-response:
                        type: int
                        description: 'Rate limit for create MBMS context response (packets per second).'
                    create-pdp-request:
                        type: int
                        description: 'Rate limit for create PDP context request (packets per second).'
                    create-pdp-response:
                        type: int
                        description: 'Rate limit for create PDP context response (packets per second).'
                    delete-aa-pdp-request:
                        type: int
                        description: 'Rate limit for delete AA PDP context request (packets per second).'
                    delete-aa-pdp-response:
                        type: int
                        description: 'Rate limit for delete AA PDP context response (packets per second).'
                    delete-mbms-request:
                        type: int
                        description: 'Rate limit for delete MBMS context request (packets per second).'
                    delete-mbms-response:
                        type: int
                        description: 'Rate limit for delete MBMS context response (packets per second).'
                    delete-pdp-request:
                        type: int
                        description: 'Rate limit for delete PDP context request (packets per second).'
                    delete-pdp-response:
                        type: int
                        description: 'Rate limit for delete PDP context response (packets per second).'
                    echo-reponse:
                        type: int
                        description: 'Rate limit for echo response (packets per second).'
                    echo-request:
                        type: int
                        description: 'Rate limit for echo requests (packets per second).'
                    error-indication:
                        type: int
                        description: 'Rate limit for error indication (packets per second).'
                    failure-report-request:
                        type: int
                        description: 'Rate limit for failure report request (packets per second).'
                    failure-report-response:
                        type: int
                        description: 'Rate limit for failure report response (packets per second).'
                    fwd-reloc-complete-ack:
                        type: int
                        description: 'Rate limit for forward relocation complete acknowledge (packets per second).'
                    fwd-relocation-complete:
                        type: int
                        description: 'Rate limit for forward relocation complete (packets per second).'
                    fwd-relocation-request:
                        type: int
                        description: 'Rate limit for forward relocation request (packets per second).'
                    fwd-relocation-response:
                        type: int
                        description: 'Rate limit for forward relocation response (packets per second).'
                    fwd-srns-context:
                        type: int
                        description: 'Rate limit for forward SRNS context (packets per second).'
                    fwd-srns-context-ack:
                        type: int
                        description: 'Rate limit for forward SRNS context acknowledge (packets per second).'
                    g-pdu:
                        type: int
                        description: 'Rate limit for G-PDU (packets per second).'
                    identification-request:
                        type: int
                        description: 'Rate limit for identification request (packets per second).'
                    identification-response:
                        type: int
                        description: 'Rate limit for identification response (packets per second).'
                    mbms-de-reg-request:
                        type: int
                        description: 'Rate limit for MBMS de-registration request (packets per second).'
                    mbms-de-reg-response:
                        type: int
                        description: 'Rate limit for MBMS de-registration response (packets per second).'
                    mbms-notify-rej-request:
                        type: int
                        description: 'Rate limit for MBMS notification reject request (packets per second).'
                    mbms-notify-rej-response:
                        type: int
                        description: 'Rate limit for MBMS notification reject response (packets per second).'
                    mbms-notify-request:
                        type: int
                        description: 'Rate limit for MBMS notification request (packets per second).'
                    mbms-notify-response:
                        type: int
                        description: 'Rate limit for MBMS notification response (packets per second).'
                    mbms-reg-request:
                        type: int
                        description: 'Rate limit for MBMS registration request (packets per second).'
                    mbms-reg-response:
                        type: int
                        description: 'Rate limit for MBMS registration response (packets per second).'
                    mbms-ses-start-request:
                        type: int
                        description: 'Rate limit for MBMS session start request (packets per second).'
                    mbms-ses-start-response:
                        type: int
                        description: 'Rate limit for MBMS session start response (packets per second).'
                    mbms-ses-stop-request:
                        type: int
                        description: 'Rate limit for MBMS session stop request (packets per second).'
                    mbms-ses-stop-response:
                        type: int
                        description: 'Rate limit for MBMS session stop response (packets per second).'
                    note-ms-request:
                        type: int
                        description: 'Rate limit for note MS GPRS present request (packets per second).'
                    note-ms-response:
                        type: int
                        description: 'Rate limit for note MS GPRS present response (packets per second).'
                    pdu-notify-rej-request:
                        type: int
                        description: 'Rate limit for PDU notify reject request (packets per second).'
                    pdu-notify-rej-response:
                        type: int
                        description: 'Rate limit for PDU notify reject response (packets per second).'
                    pdu-notify-request:
                        type: int
                        description: 'Rate limit for PDU notify request (packets per second).'
                    pdu-notify-response:
                        type: int
                        description: 'Rate limit for PDU notify response (packets per second).'
                    ran-info:
                        type: int
                        description: 'Rate limit for RAN information relay (packets per second).'
                    relocation-cancel-request:
                        type: int
                        description: 'Rate limit for relocation cancel request (packets per second).'
                    relocation-cancel-response:
                        type: int
                        description: 'Rate limit for relocation cancel response (packets per second).'
                    send-route-request:
                        type: int
                        description: 'Rate limit for send routing information for GPRS request (packets per second).'
                    send-route-response:
                        type: int
                        description: 'Rate limit for send routing information for GPRS response (packets per second).'
                    sgsn-context-ack:
                        type: int
                        description: 'Rate limit for SGSN context acknowledgement (packets per second).'
                    sgsn-context-request:
                        type: int
                        description: 'Rate limit for SGSN context request (packets per second).'
                    sgsn-context-response:
                        type: int
                        description: 'Rate limit for SGSN context response (packets per second).'
                    support-ext-hdr-notify:
                        type: int
                        description: 'Rate limit for support extension headers notification (packets per second).'
                    update-mbms-request:
                        type: int
                        description: 'Rate limit for update MBMS context request (packets per second).'
                    update-mbms-response:
                        type: int
                        description: 'Rate limit for update MBMS context response (packets per second).'
                    update-pdp-request:
                        type: int
                        description: 'Rate limit for update PDP context request (packets per second).'
                    update-pdp-response:
                        type: int
                        description: 'Rate limit for update PDP context response (packets per second).'
                    version-not-support:
                        type: int
                        description: 'Rate limit for version not supported (packets per second).'
            message-rate-limit-v0:
                description: no description
                type: dict
                required: false
                suboptions:
                    create-pdp-request:
                        type: int
                        description: 'Rate limit (packets/s) for create PDP context request.'
                    delete-pdp-request:
                        type: int
                        description: 'Rate limit (packets/s) for delete PDP context request.'
                    echo-request:
                        type: int
                        description: 'Rate limit (packets/s) for echo request.'
            message-rate-limit-v1:
                description: no description
                type: dict
                required: false
                suboptions:
                    create-pdp-request:
                        type: int
                        description: 'Rate limit (packets/s) for create PDP context request.'
                    delete-pdp-request:
                        type: int
                        description: 'Rate limit (packets/s) for delete PDP context request.'
                    echo-request:
                        type: int
                        description: 'Rate limit (packets/s) for echo request.'
            message-rate-limit-v2:
                description: no description
                type: dict
                required: false
                suboptions:
                    create-session-request:
                        type: int
                        description: 'Rate limit (packets/s) for create session request.'
                    delete-session-request:
                        type: int
                        description: 'Rate limit (packets/s) for delete session request.'
                    echo-request:
                        type: int
                        description: 'Rate limit (packets/s) for echo request.'
            ie-allow-list-v0v1:
                type: str
                description: 'IE allow list.'
            ie-allow-list-v2:
                type: str
                description: 'IE allow list.'

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
                  sgsn-addr6: <value of string>
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
                  dstaddr6: <value of string>
                  srcaddr6: <value of string>
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
                  imsi-prefix: <value of string>
                  msisdn-prefix: <value of string>
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
            policy-v2:
              -
                  action: <value in [deny, allow]>
                  apn-sel-mode:
                    - ms
                    - net
                    - vrf
                  apnmember: <value of string>
                  id: <value of integer>
                  imsi-prefix: <value of string>
                  max-apn-restriction: <value in [all, public-1, public-2, ...]>
                  mei: <value of string>
                  messages:
                    - create-ses-req
                    - create-ses-res
                    - modify-bearer-req
                    - modify-bearer-res
                  msisdn-prefix: <value of string>
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
                    - ltem
                    - nr
                  uli: <value of string>
            sub-second-interval: <value in [0.1, 0.25, 0.5]>
            sub-second-sampling: <value in [disable, enable]>
            authorized-ggsns6: <value of string>
            authorized-sgsns6: <value of string>
            handover-group6: <value of string>
            invalid-sgsns6-to-log: <value of string>
            ie-validation:
               apn-restriction: <value in [disable, enable]>
               charging-ID: <value in [disable, enable]>
               charging-gateway-addr: <value in [disable, enable]>
               end-user-addr: <value in [disable, enable]>
               gsn-addr: <value in [disable, enable]>
               imei: <value in [disable, enable]>
               imsi: <value in [disable, enable]>
               mm-context: <value in [disable, enable]>
               ms-tzone: <value in [disable, enable]>
               ms-validated: <value in [disable, enable]>
               msisdn: <value in [disable, enable]>
               nsapi: <value in [disable, enable]>
               pdp-context: <value in [disable, enable]>
               qos-profile: <value in [disable, enable]>
               rai: <value in [disable, enable]>
               rat-type: <value in [disable, enable]>
               reordering-required: <value in [disable, enable]>
               selection-mode: <value in [disable, enable]>
               uli: <value in [disable, enable]>
            message-rate-limit:
               create-aa-pdp-request: <value of integer>
               create-aa-pdp-response: <value of integer>
               create-mbms-request: <value of integer>
               create-mbms-response: <value of integer>
               create-pdp-request: <value of integer>
               create-pdp-response: <value of integer>
               delete-aa-pdp-request: <value of integer>
               delete-aa-pdp-response: <value of integer>
               delete-mbms-request: <value of integer>
               delete-mbms-response: <value of integer>
               delete-pdp-request: <value of integer>
               delete-pdp-response: <value of integer>
               echo-reponse: <value of integer>
               echo-request: <value of integer>
               error-indication: <value of integer>
               failure-report-request: <value of integer>
               failure-report-response: <value of integer>
               fwd-reloc-complete-ack: <value of integer>
               fwd-relocation-complete: <value of integer>
               fwd-relocation-request: <value of integer>
               fwd-relocation-response: <value of integer>
               fwd-srns-context: <value of integer>
               fwd-srns-context-ack: <value of integer>
               g-pdu: <value of integer>
               identification-request: <value of integer>
               identification-response: <value of integer>
               mbms-de-reg-request: <value of integer>
               mbms-de-reg-response: <value of integer>
               mbms-notify-rej-request: <value of integer>
               mbms-notify-rej-response: <value of integer>
               mbms-notify-request: <value of integer>
               mbms-notify-response: <value of integer>
               mbms-reg-request: <value of integer>
               mbms-reg-response: <value of integer>
               mbms-ses-start-request: <value of integer>
               mbms-ses-start-response: <value of integer>
               mbms-ses-stop-request: <value of integer>
               mbms-ses-stop-response: <value of integer>
               note-ms-request: <value of integer>
               note-ms-response: <value of integer>
               pdu-notify-rej-request: <value of integer>
               pdu-notify-rej-response: <value of integer>
               pdu-notify-request: <value of integer>
               pdu-notify-response: <value of integer>
               ran-info: <value of integer>
               relocation-cancel-request: <value of integer>
               relocation-cancel-response: <value of integer>
               send-route-request: <value of integer>
               send-route-response: <value of integer>
               sgsn-context-ack: <value of integer>
               sgsn-context-request: <value of integer>
               sgsn-context-response: <value of integer>
               support-ext-hdr-notify: <value of integer>
               update-mbms-request: <value of integer>
               update-mbms-response: <value of integer>
               update-pdp-request: <value of integer>
               update-pdp-response: <value of integer>
               version-not-support: <value of integer>
            message-rate-limit-v0:
               create-pdp-request: <value of integer>
               delete-pdp-request: <value of integer>
               echo-request: <value of integer>
            message-rate-limit-v1:
               create-pdp-request: <value of integer>
               delete-pdp-request: <value of integer>
               echo-request: <value of integer>
            message-rate-limit-v2:
               create-session-request: <value of integer>
               delete-session-request: <value of integer>
               echo-request: <value of integer>
            ie-allow-list-v0v1: <value of string>
            ie-allow-list-v2: <value of string>

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
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'firewall_gtp': {
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
                '7.0.0': True
            },
            'options': {
                'addr-notify': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'apn': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apnmember': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'selection-mode': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'authorized-ggsns': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'authorized-sgsns': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'context-id': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'control-plane-message-rate-limit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'default-apn-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-imsi-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-ip-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-noip-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'default-policy-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'denied-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'echo-request-interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'extension-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'forwarded-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'global-tunnel-limit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'gtp-in-gtp': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'gtpu-denied-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gtpu-forwarded-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gtpu-log-freq': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'half-close-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'half-open-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'handover-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ie-remove-policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'remove-ies': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'sgsn-addr6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'ie-remover': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ie-white-list-v0v1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'ie-white-list-v2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'imsi': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apnmember': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mcc-mnc': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'msisdn-prefix': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'selection-mode': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'interface-notify': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'invalid-reserved-field': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'invalid-sgsns-to-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ip-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip-policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'dstaddr': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'srcaddr': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'dstaddr6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'srcaddr6': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'log-freq': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'log-gtpu-limit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'log-imsi-prefix': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'log-msisdn-prefix': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'max-message-length': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'message-filter-v0v1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'message-filter-v2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'min-message-length': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'miss-must-ie': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'monitor-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'vdom'
                    ],
                    'type': 'str'
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'noip-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'noip-policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'end': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'start': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'out-of-state-message': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'per-apn-shaper': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'apn': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'rate-limit': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'version': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'apn-sel-mode': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'ms',
                                'net',
                                'vrf'
                            ]
                        },
                        'apnmember': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'imei': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'imsi': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'max-apn-restriction': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'rai': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'rat-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'imsi-prefix': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'msisdn-prefix': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'policy-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'port-notify': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'rate-limit-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'per-profile',
                        'per-stream',
                        'per-apn'
                    ],
                    'type': 'str'
                },
                'rate-limited-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-sampling-interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'remove-if-echo-expires': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'remove-if-recovery-differ': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'reserved-ie': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'send-delete-when-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'send-delete-when-timeout-v2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'spoof-src-addr': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'state-invalid-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'traffic-count-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-limit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'tunnel-limit-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tunnel-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'unknown-version-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'allow',
                        'deny'
                    ],
                    'type': 'str'
                },
                'user-plane-message-rate-limit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'warning-threshold': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'policy-v2': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'deny',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'apn-sel-mode': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'ms',
                                'net',
                                'vrf'
                            ]
                        },
                        'apnmember': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'imsi-prefix': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'max-apn-restriction': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'all',
                                'public-1',
                                'public-2',
                                'private-1',
                                'private-2'
                            ],
                            'type': 'str'
                        },
                        'mei': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'messages': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'create-ses-req',
                                'create-ses-res',
                                'modify-bearer-req',
                                'modify-bearer-res'
                            ]
                        },
                        'msisdn-prefix': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'rat-type': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                                'nbiot',
                                'ltem',
                                'nr'
                            ]
                        },
                        'uli': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'sub-second-interval': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        '0.1',
                        '0.25',
                        '0.5'
                    ],
                    'type': 'str'
                },
                'sub-second-sampling': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'authorized-ggsns6': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'authorized-sgsns6': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'handover-group6': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'invalid-sgsns6-to-log': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ie-validation': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'apn-restriction': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charging-ID': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charging-gateway-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'end-user-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'gsn-addr': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'imei': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'imsi': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'mm-context': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ms-tzone': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ms-validated': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'msisdn': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'nsapi': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pdp-context': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'qos-profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'rai': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'rat-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'reordering-required': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'selection-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uli': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'message-rate-limit': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'create-aa-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'create-aa-pdp-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'create-mbms-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'create-mbms-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'create-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'create-pdp-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-aa-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-aa-pdp-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-mbms-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-mbms-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-pdp-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'echo-reponse': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'echo-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'error-indication': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'failure-report-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'failure-report-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-reloc-complete-ack': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-relocation-complete': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-relocation-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-relocation-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-srns-context': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fwd-srns-context-ack': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'g-pdu': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'identification-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'identification-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-de-reg-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-de-reg-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-notify-rej-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-notify-rej-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-notify-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-notify-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-reg-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-reg-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-ses-start-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-ses-start-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-ses-stop-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'mbms-ses-stop-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'note-ms-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'note-ms-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'pdu-notify-rej-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'pdu-notify-rej-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'pdu-notify-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'pdu-notify-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ran-info': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'relocation-cancel-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'relocation-cancel-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'send-route-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'send-route-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'sgsn-context-ack': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'sgsn-context-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'sgsn-context-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'support-ext-hdr-notify': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'update-mbms-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'update-mbms-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'update-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'update-pdp-response': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'version-not-support': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'message-rate-limit-v0': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'create-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'echo-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'message-rate-limit-v1': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'create-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-pdp-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'echo-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'message-rate-limit-v2': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'create-session-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'delete-session-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'echo-request': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'ie-allow-list-v0v1': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ie-allow-list-v2': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
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
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
