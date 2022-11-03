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
module: fmgr_voip_profile_sip
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
    profile:
        description: the parameter (profile) in requested url
        type: str
        required: true
    voip_profile_sip:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            ack-rate:
                type: int
                description: no description
            block-ack:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-bye:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-cancel:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-geo-red-options:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-info:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-invite:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-long-lines:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-message:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-notify:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-options:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-prack:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-publish:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-refer:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-register:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-subscribe:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-unknown:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-update:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            bye-rate:
                type: int
                description: no description
            call-keepalive:
                type: int
                description: no description
            cancel-rate:
                type: int
                description: no description
            contact-fixup:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            hnt-restrict-source-ip:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            hosted-nat-traversal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            info-rate:
                type: int
                description: no description
            invite-rate:
                type: int
                description: no description
            ips-rtp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            log-call-summary:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            log-violations:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            malformed-header-allow:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-call-id:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-contact:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-content-length:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-content-type:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-cseq:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-expires:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-from:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-max-forwards:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-p-asserted-identity:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-rack:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-record-route:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-route:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-rseq:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-a:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-b:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-c:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-i:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-k:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-m:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-o:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-r:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-s:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-t:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-v:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-sdp-z:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-to:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-via:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-request-line:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            max-body-length:
                type: int
                description: no description
            max-dialogs:
                type: int
                description: no description
            max-idle-dialogs:
                type: int
                description: no description
            max-line-length:
                type: int
                description: no description
            message-rate:
                type: int
                description: no description
            nat-trace:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            no-sdp-fixup:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            notify-rate:
                type: int
                description: no description
            open-contact-pinhole:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            open-record-route-pinhole:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            open-register-pinhole:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            open-via-pinhole:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            options-rate:
                type: int
                description: no description
            prack-rate:
                type: int
                description: no description
            preserve-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            provisional-invite-expiry-time:
                type: int
                description: no description
            publish-rate:
                type: int
                description: no description
            refer-rate:
                type: int
                description: no description
            register-contact-trace:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            register-rate:
                type: int
                description: no description
            rfc2543-branch:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rtp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-algorithm:
                type: str
                description: no description
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl-auth-client:
                type: str
                description: no description
            ssl-auth-server:
                type: str
                description: no description
            ssl-client-certificate:
                type: str
                description: no description
            ssl-client-renegotiation:
                type: str
                description: no description
                choices:
                    - 'allow'
                    - 'deny'
                    - 'secure'
            ssl-max-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-min-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-mode:
                type: str
                description: no description
                choices:
                    - 'off'
                    - 'full'
            ssl-pfs:
                type: str
                description: no description
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl-send-empty-frags:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server-certificate:
                type: str
                description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            strict-register:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            subscribe-rate:
                type: int
                description: no description
            unknown-header:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            update-rate:
                type: int
                description: no description
            nat-port-range:
                type: str
                description: no description
            ack-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            bye-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            cancel-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            info-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            invite-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            malformed-header-no-proxy-require:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed-header-no-require:
                type: str
                description: no description
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            message-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            notify-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            options-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            prack-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            publish-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            refer-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            register-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            subscribe-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            update-rate-track:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'

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
      fmgr_voip_profile_sip:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         profile: <your own value>
         voip_profile_sip:
            ack-rate: <value of integer>
            block-ack: <value in [disable, enable]>
            block-bye: <value in [disable, enable]>
            block-cancel: <value in [disable, enable]>
            block-geo-red-options: <value in [disable, enable]>
            block-info: <value in [disable, enable]>
            block-invite: <value in [disable, enable]>
            block-long-lines: <value in [disable, enable]>
            block-message: <value in [disable, enable]>
            block-notify: <value in [disable, enable]>
            block-options: <value in [disable, enable]>
            block-prack: <value in [disable, enable]>
            block-publish: <value in [disable, enable]>
            block-refer: <value in [disable, enable]>
            block-register: <value in [disable, enable]>
            block-subscribe: <value in [disable, enable]>
            block-unknown: <value in [disable, enable]>
            block-update: <value in [disable, enable]>
            bye-rate: <value of integer>
            call-keepalive: <value of integer>
            cancel-rate: <value of integer>
            contact-fixup: <value in [disable, enable]>
            hnt-restrict-source-ip: <value in [disable, enable]>
            hosted-nat-traversal: <value in [disable, enable]>
            info-rate: <value of integer>
            invite-rate: <value of integer>
            ips-rtp: <value in [disable, enable]>
            log-call-summary: <value in [disable, enable]>
            log-violations: <value in [disable, enable]>
            malformed-header-allow: <value in [pass, discard, respond]>
            malformed-header-call-id: <value in [pass, discard, respond]>
            malformed-header-contact: <value in [pass, discard, respond]>
            malformed-header-content-length: <value in [pass, discard, respond]>
            malformed-header-content-type: <value in [pass, discard, respond]>
            malformed-header-cseq: <value in [pass, discard, respond]>
            malformed-header-expires: <value in [pass, discard, respond]>
            malformed-header-from: <value in [pass, discard, respond]>
            malformed-header-max-forwards: <value in [pass, discard, respond]>
            malformed-header-p-asserted-identity: <value in [pass, discard, respond]>
            malformed-header-rack: <value in [pass, discard, respond]>
            malformed-header-record-route: <value in [pass, discard, respond]>
            malformed-header-route: <value in [pass, discard, respond]>
            malformed-header-rseq: <value in [pass, discard, respond]>
            malformed-header-sdp-a: <value in [pass, discard, respond]>
            malformed-header-sdp-b: <value in [pass, discard, respond]>
            malformed-header-sdp-c: <value in [pass, discard, respond]>
            malformed-header-sdp-i: <value in [pass, discard, respond]>
            malformed-header-sdp-k: <value in [pass, discard, respond]>
            malformed-header-sdp-m: <value in [pass, discard, respond]>
            malformed-header-sdp-o: <value in [pass, discard, respond]>
            malformed-header-sdp-r: <value in [pass, discard, respond]>
            malformed-header-sdp-s: <value in [pass, discard, respond]>
            malformed-header-sdp-t: <value in [pass, discard, respond]>
            malformed-header-sdp-v: <value in [pass, discard, respond]>
            malformed-header-sdp-z: <value in [pass, discard, respond]>
            malformed-header-to: <value in [pass, discard, respond]>
            malformed-header-via: <value in [pass, discard, respond]>
            malformed-request-line: <value in [pass, discard, respond]>
            max-body-length: <value of integer>
            max-dialogs: <value of integer>
            max-idle-dialogs: <value of integer>
            max-line-length: <value of integer>
            message-rate: <value of integer>
            nat-trace: <value in [disable, enable]>
            no-sdp-fixup: <value in [disable, enable]>
            notify-rate: <value of integer>
            open-contact-pinhole: <value in [disable, enable]>
            open-record-route-pinhole: <value in [disable, enable]>
            open-register-pinhole: <value in [disable, enable]>
            open-via-pinhole: <value in [disable, enable]>
            options-rate: <value of integer>
            prack-rate: <value of integer>
            preserve-override: <value in [disable, enable]>
            provisional-invite-expiry-time: <value of integer>
            publish-rate: <value of integer>
            refer-rate: <value of integer>
            register-contact-trace: <value in [disable, enable]>
            register-rate: <value of integer>
            rfc2543-branch: <value in [disable, enable]>
            rtp: <value in [disable, enable]>
            ssl-algorithm: <value in [high, medium, low]>
            ssl-auth-client: <value of string>
            ssl-auth-server: <value of string>
            ssl-client-certificate: <value of string>
            ssl-client-renegotiation: <value in [allow, deny, secure]>
            ssl-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-mode: <value in [off, full]>
            ssl-pfs: <value in [require, deny, allow]>
            ssl-send-empty-frags: <value in [disable, enable]>
            ssl-server-certificate: <value of string>
            status: <value in [disable, enable]>
            strict-register: <value in [disable, enable]>
            subscribe-rate: <value of integer>
            unknown-header: <value in [pass, discard, respond]>
            update-rate: <value of integer>
            nat-port-range: <value of string>
            ack-rate-track: <value in [none, src-ip, dest-ip]>
            bye-rate-track: <value in [none, src-ip, dest-ip]>
            cancel-rate-track: <value in [none, src-ip, dest-ip]>
            info-rate-track: <value in [none, src-ip, dest-ip]>
            invite-rate-track: <value in [none, src-ip, dest-ip]>
            malformed-header-no-proxy-require: <value in [pass, discard, respond]>
            malformed-header-no-require: <value in [pass, discard, respond]>
            message-rate-track: <value in [none, src-ip, dest-ip]>
            notify-rate-track: <value in [none, src-ip, dest-ip]>
            options-rate-track: <value in [none, src-ip, dest-ip]>
            prack-rate-track: <value in [none, src-ip, dest-ip]>
            publish-rate-track: <value in [none, src-ip, dest-ip]>
            refer-rate-track: <value in [none, src-ip, dest-ip]>
            register-rate-track: <value in [none, src-ip, dest-ip]>
            subscribe-rate-track: <value in [none, src-ip, dest-ip]>
            update-rate-track: <value in [none, src-ip, dest-ip]>

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
        '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sip',
        '/pm/config/global/obj/voip/profile/{profile}/sip'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sip/{sip}',
        '/pm/config/global/obj/voip/profile/{profile}/sip/{sip}'
    ]

    url_params = ['adom', 'profile']
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
        'profile': {
            'required': True,
            'type': 'str'
        },
        'voip_profile_sip': {
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
                'ack-rate': {
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
                'block-ack': {
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
                'block-bye': {
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
                'block-cancel': {
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
                'block-geo-red-options': {
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
                'block-info': {
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
                'block-invite': {
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
                'block-long-lines': {
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
                'block-message': {
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
                'block-notify': {
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
                'block-options': {
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
                'block-prack': {
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
                'block-publish': {
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
                'block-refer': {
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
                'block-register': {
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
                'block-subscribe': {
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
                'block-unknown': {
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
                'block-update': {
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
                'bye-rate': {
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
                'call-keepalive': {
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
                'cancel-rate': {
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
                'contact-fixup': {
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
                'hnt-restrict-source-ip': {
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
                'hosted-nat-traversal': {
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
                'info-rate': {
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
                'invite-rate': {
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
                'ips-rtp': {
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
                'log-call-summary': {
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
                'log-violations': {
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
                'malformed-header-allow': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-call-id': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-contact': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-content-length': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-content-type': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-cseq': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-expires': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-from': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-max-forwards': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-p-asserted-identity': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-rack': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-record-route': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-route': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-rseq': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-a': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-b': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-c': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-i': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-k': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-m': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-o': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-r': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-s': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-t': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-v': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-sdp-z': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-to': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-via': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-request-line': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'max-body-length': {
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
                'max-dialogs': {
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
                'max-idle-dialogs': {
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
                'max-line-length': {
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
                'message-rate': {
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
                'nat-trace': {
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
                'no-sdp-fixup': {
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
                'notify-rate': {
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
                'open-contact-pinhole': {
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
                'open-record-route-pinhole': {
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
                'open-register-pinhole': {
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
                'open-via-pinhole': {
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
                'options-rate': {
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
                'prack-rate': {
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
                'preserve-override': {
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
                'provisional-invite-expiry-time': {
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
                'publish-rate': {
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
                'refer-rate': {
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
                'register-contact-trace': {
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
                'register-rate': {
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
                'rfc2543-branch': {
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
                'rtp': {
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
                'ssl-algorithm': {
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
                        'high',
                        'medium',
                        'low'
                    ],
                    'type': 'str'
                },
                'ssl-auth-client': {
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
                'ssl-auth-server': {
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
                'ssl-client-certificate': {
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
                'ssl-client-renegotiation': {
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
                        'allow',
                        'deny',
                        'secure'
                    ],
                    'type': 'str'
                },
                'ssl-max-version': {
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
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'tls-1.3'
                    ],
                    'type': 'str'
                },
                'ssl-min-version': {
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
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'tls-1.3'
                    ],
                    'type': 'str'
                },
                'ssl-mode': {
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
                        'off',
                        'full'
                    ],
                    'type': 'str'
                },
                'ssl-pfs': {
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
                        'require',
                        'deny',
                        'allow'
                    ],
                    'type': 'str'
                },
                'ssl-send-empty-frags': {
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
                'ssl-server-certificate': {
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
                'status': {
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
                'strict-register': {
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
                'subscribe-rate': {
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
                'unknown-header': {
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
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'update-rate': {
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
                'nat-port-range': {
                    'required': False,
                    'revision': {
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
                'ack-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'bye-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'cancel-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'info-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'invite-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'malformed-header-no-proxy-require': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'malformed-header-no-require': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'pass',
                        'discard',
                        'respond'
                    ],
                    'type': 'str'
                },
                'message-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'notify-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'options-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'prack-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'publish-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'refer-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'register-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'subscribe-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                },
                'update-rate-track': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'src-ip',
                        'dest-ip'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'voip_profile_sip'),
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
