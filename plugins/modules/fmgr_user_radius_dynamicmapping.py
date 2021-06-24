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
module: fmgr_user_radius_dynamicmapping
short_description: Configure RADIUS server entries.
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
    radius:
        description: the parameter (radius) in requested url
        type: str
        required: true
    user_radius_dynamicmapping:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
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
            acct-all-servers:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            acct-interim-interval:
                type: int
                description: no description
            all-usergroup:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auth-type:
                type: str
                description: no description
                choices:
                    - 'pap'
                    - 'chap'
                    - 'ms_chap'
                    - 'ms_chap_v2'
                    - 'auto'
            class:
                description: no description
                type: str
            dp-carrier-endpoint-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Vendor-Specific'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            dp-carrier-endpoint-block-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Vendor-Specific'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            dp-context-timeout:
                type: int
                description: no description
            dp-flush-ip-session:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dp-hold-time:
                type: int
                description: no description
            dp-http-header:
                type: str
                description: no description
            dp-http-header-fallback:
                type: str
                description: no description
                choices:
                    - 'ip-header-address'
                    - 'default-profile'
            dp-http-header-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dp-http-header-suppress:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dp-log-dyn_flags:
                description: no description
                type: list
                choices:
                 - none
                 - protocol-error
                 - profile-missing
                 - context-missing
                 - accounting-stop-missed
                 - accounting-event
                 - radiusd-other
                 - endpoint-block
            dp-log-period:
                type: int
                description: no description
            dp-mem-percent:
                type: int
                description: no description
            dp-profile-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Vendor-Specific'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            dp-profile-attribute-key:
                type: str
                description: no description
            dp-radius-response:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dp-radius-server-port:
                type: int
                description: no description
            dp-secret:
                description: no description
                type: str
            dp-validate-request-secret:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-translation:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-convert-hex:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-header:
                type: str
                description: no description
            ep-carrier-endpoint-header-suppress:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-prefix:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-prefix-range-max:
                type: int
                description: no description
            ep-carrier-endpoint-prefix-range-min:
                type: int
                description: no description
            ep-carrier-endpoint-prefix-string:
                type: str
                description: no description
            ep-carrier-endpoint-source:
                type: str
                description: no description
                choices:
                    - 'http-header'
                    - 'cookie'
            ep-ip-header:
                type: str
                description: no description
            ep-ip-header-suppress:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ep-missing-header-fallback:
                type: str
                description: no description
                choices:
                    - 'session-ip'
                    - 'policy-profile'
            ep-profile-query-type:
                type: str
                description: no description
                choices:
                    - 'session-ip'
                    - 'extract-ip'
                    - 'extract-carrier-endpoint'
            h3c-compatibility:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            nas-ip:
                type: str
                description: no description
            password-encoding:
                type: str
                description: no description
                choices:
                    - 'ISO-8859-1'
                    - 'auto'
            password-renewal:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            radius-coa:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            radius-port:
                type: int
                description: no description
            rsso:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rsso-context-timeout:
                type: int
                description: no description
            rsso-endpoint-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            rsso-endpoint-block-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            rsso-ep-one-ip-only:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rsso-flush-ip-session:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rsso-log-flags:
                description: no description
                type: list
                choices:
                 - none
                 - protocol-error
                 - profile-missing
                 - context-missing
                 - accounting-stop-missed
                 - accounting-event
                 - radiusd-other
                 - endpoint-block
            rsso-log-period:
                type: int
                description: no description
            rsso-radius-response:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rsso-radius-server-port:
                type: int
                description: no description
            rsso-secret:
                description: no description
                type: str
            rsso-validate-request-secret:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            secondary-secret:
                description: no description
                type: str
            secondary-server:
                type: str
                description: no description
            secret:
                description: no description
                type: str
            server:
                type: str
                description: no description
            source-ip:
                type: str
                description: no description
            sso-attribute:
                type: str
                description: no description
                choices:
                    - 'User-Name'
                    - 'User-Password'
                    - 'CHAP-Password'
                    - 'NAS-IP-Address'
                    - 'NAS-Port'
                    - 'Service-Type'
                    - 'Framed-Protocol'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Framed-Routing'
                    - 'Filter-Id'
                    - 'Framed-MTU'
                    - 'Framed-Compression'
                    - 'Login-IP-Host'
                    - 'Login-Service'
                    - 'Login-TCP-Port'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'State'
                    - 'Class'
                    - 'Session-Timeout'
                    - 'Idle-Timeout'
                    - 'Termination-Action'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Link'
                    - 'Framed-AppleTalk-Network'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Status-Type'
                    - 'Acct-Delay-Time'
                    - 'Acct-Input-Octets'
                    - 'Acct-Output-Octets'
                    - 'Acct-Session-Id'
                    - 'Acct-Authentic'
                    - 'Acct-Session-Time'
                    - 'Acct-Input-Packets'
                    - 'Acct-Output-Packets'
                    - 'Acct-Terminate-Cause'
                    - 'Acct-Multi-Session-Id'
                    - 'Acct-Link-Count'
                    - 'CHAP-Challenge'
                    - 'NAS-Port-Type'
                    - 'Port-Limit'
                    - 'Login-LAT-Port'
            sso-attribute-key:
                type: str
                description: no description
            sso-attribute-value-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tertiary-secret:
                description: no description
                type: str
            tertiary-server:
                type: str
                description: no description
            timeout:
                type: int
                description: no description
            use-group-for-profile:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            use-management-vdom:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            username-case-sensitive:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: str
                description: no description
            interface-select-method:
                type: str
                description: no description
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            group-override-attr-type:
                type: str
                description: no description
                choices:
                    - 'filter-Id'
                    - 'class'
            switch-controller-acct-fast-framedip-detect:
                type: int
                description: no description
            accounting-server:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: no description
                    interface:
                        type: str
                        description: no description
                    interface-select-method:
                        type: str
                        description: no description
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    port:
                        type: int
                        description: no description
                    secret:
                        description: no description
                        type: str
                    server:
                        type: str
                        description: no description
                    source-ip:
                        type: str
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            switch-controller-service-type:
                description: no description
                type: list
                choices:
                 - login
                 - framed
                 - callback-login
                 - callback-framed
                 - outbound
                 - administrative
                 - nas-prompt
                 - authenticate-only
                 - callback-nas-prompt
                 - call-check
                 - callback-administrative

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
    - name: Configure RADIUS server entries.
      fmgr_user_radius_dynamicmapping:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         radius: <your own value>
         state: <value in [present, absent]>
         user_radius_dynamicmapping:
            _scope:
              -
                  name: <value of string>
                  vdom: <value of string>
            acct-all-servers: <value in [disable, enable]>
            acct-interim-interval: <value of integer>
            all-usergroup: <value in [disable, enable]>
            auth-type: <value in [pap, chap, ms_chap, ...]>
            class: <value of string>
            dp-carrier-endpoint-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            dp-carrier-endpoint-block-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            dp-context-timeout: <value of integer>
            dp-flush-ip-session: <value in [disable, enable]>
            dp-hold-time: <value of integer>
            dp-http-header: <value of string>
            dp-http-header-fallback: <value in [ip-header-address, default-profile]>
            dp-http-header-status: <value in [disable, enable]>
            dp-http-header-suppress: <value in [disable, enable]>
            dp-log-dyn_flags:
              - none
              - protocol-error
              - profile-missing
              - context-missing
              - accounting-stop-missed
              - accounting-event
              - radiusd-other
              - endpoint-block
            dp-log-period: <value of integer>
            dp-mem-percent: <value of integer>
            dp-profile-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            dp-profile-attribute-key: <value of string>
            dp-radius-response: <value in [disable, enable]>
            dp-radius-server-port: <value of integer>
            dp-secret: <value of string>
            dp-validate-request-secret: <value in [disable, enable]>
            dynamic-profile: <value in [disable, enable]>
            endpoint-translation: <value in [disable, enable]>
            ep-carrier-endpoint-convert-hex: <value in [disable, enable]>
            ep-carrier-endpoint-header: <value of string>
            ep-carrier-endpoint-header-suppress: <value in [disable, enable]>
            ep-carrier-endpoint-prefix: <value in [disable, enable]>
            ep-carrier-endpoint-prefix-range-max: <value of integer>
            ep-carrier-endpoint-prefix-range-min: <value of integer>
            ep-carrier-endpoint-prefix-string: <value of string>
            ep-carrier-endpoint-source: <value in [http-header, cookie]>
            ep-ip-header: <value of string>
            ep-ip-header-suppress: <value in [disable, enable]>
            ep-missing-header-fallback: <value in [session-ip, policy-profile]>
            ep-profile-query-type: <value in [session-ip, extract-ip, extract-carrier-endpoint]>
            h3c-compatibility: <value in [disable, enable]>
            nas-ip: <value of string>
            password-encoding: <value in [ISO-8859-1, auto]>
            password-renewal: <value in [disable, enable]>
            radius-coa: <value in [disable, enable]>
            radius-port: <value of integer>
            rsso: <value in [disable, enable]>
            rsso-context-timeout: <value of integer>
            rsso-endpoint-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            rsso-endpoint-block-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            rsso-ep-one-ip-only: <value in [disable, enable]>
            rsso-flush-ip-session: <value in [disable, enable]>
            rsso-log-flags:
              - none
              - protocol-error
              - profile-missing
              - context-missing
              - accounting-stop-missed
              - accounting-event
              - radiusd-other
              - endpoint-block
            rsso-log-period: <value of integer>
            rsso-radius-response: <value in [disable, enable]>
            rsso-radius-server-port: <value of integer>
            rsso-secret: <value of string>
            rsso-validate-request-secret: <value in [disable, enable]>
            secondary-secret: <value of string>
            secondary-server: <value of string>
            secret: <value of string>
            server: <value of string>
            source-ip: <value of string>
            sso-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
            sso-attribute-key: <value of string>
            sso-attribute-value-override: <value in [disable, enable]>
            tertiary-secret: <value of string>
            tertiary-server: <value of string>
            timeout: <value of integer>
            use-group-for-profile: <value in [disable, enable]>
            use-management-vdom: <value in [disable, enable]>
            username-case-sensitive: <value in [disable, enable]>
            interface: <value of string>
            interface-select-method: <value in [auto, sdwan, specify]>
            group-override-attr-type: <value in [filter-Id, class]>
            switch-controller-acct-fast-framedip-detect: <value of integer>
            accounting-server:
              -
                  id: <value of integer>
                  interface: <value of string>
                  interface-select-method: <value in [auto, sdwan, specify]>
                  port: <value of integer>
                  secret: <value of string>
                  server: <value of string>
                  source-ip: <value of string>
                  status: <value in [disable, enable]>
            switch-controller-service-type:
              - login
              - framed
              - callback-login
              - callback-framed
              - outbound
              - administrative
              - nas-prompt
              - authenticate-only
              - callback-nas-prompt
              - call-check
              - callback-administrative

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
        '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping',
        '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'radius']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
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
        'radius': {
            'required': True,
            'type': 'str'
        },
        'user_radius_dynamicmapping': {
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
                        '7.0.0': True
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
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'acct-all-servers': {
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
                'acct-interim-interval': {
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
                'all-usergroup': {
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
                'auth-type': {
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
                        'pap',
                        'chap',
                        'ms_chap',
                        'ms_chap_v2',
                        'auto'
                    ],
                    'type': 'str'
                },
                'class': {
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
                'dp-carrier-endpoint-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Vendor-Specific',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-carrier-endpoint-block-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Vendor-Specific',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-context-timeout': {
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
                'dp-flush-ip-session': {
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
                'dp-hold-time': {
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
                'dp-http-header': {
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
                'dp-http-header-fallback': {
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
                        'ip-header-address',
                        'default-profile'
                    ],
                    'type': 'str'
                },
                'dp-http-header-status': {
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
                'dp-http-header-suppress': {
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
                'dp-log-dyn_flags': {
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
                        'none',
                        'protocol-error',
                        'profile-missing',
                        'context-missing',
                        'accounting-stop-missed',
                        'accounting-event',
                        'radiusd-other',
                        'endpoint-block'
                    ]
                },
                'dp-log-period': {
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
                'dp-mem-percent': {
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
                'dp-profile-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Vendor-Specific',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-profile-attribute-key': {
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
                'dp-radius-response': {
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
                'dp-radius-server-port': {
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
                'dp-secret': {
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
                'dp-validate-request-secret': {
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
                'dynamic-profile': {
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
                'endpoint-translation': {
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
                'ep-carrier-endpoint-convert-hex': {
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
                'ep-carrier-endpoint-header': {
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
                'ep-carrier-endpoint-header-suppress': {
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
                'ep-carrier-endpoint-prefix': {
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
                'ep-carrier-endpoint-prefix-range-max': {
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
                'ep-carrier-endpoint-prefix-range-min': {
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
                'ep-carrier-endpoint-prefix-string': {
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
                'ep-carrier-endpoint-source': {
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
                        'http-header',
                        'cookie'
                    ],
                    'type': 'str'
                },
                'ep-ip-header': {
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
                'ep-ip-header-suppress': {
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
                'ep-missing-header-fallback': {
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
                        'session-ip',
                        'policy-profile'
                    ],
                    'type': 'str'
                },
                'ep-profile-query-type': {
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
                        'session-ip',
                        'extract-ip',
                        'extract-carrier-endpoint'
                    ],
                    'type': 'str'
                },
                'h3c-compatibility': {
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
                'nas-ip': {
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
                'password-encoding': {
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
                        'ISO-8859-1',
                        'auto'
                    ],
                    'type': 'str'
                },
                'password-renewal': {
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
                'radius-coa': {
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
                'radius-port': {
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
                'rsso': {
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
                'rsso-context-timeout': {
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
                'rsso-endpoint-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'rsso-endpoint-block-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'rsso-ep-one-ip-only': {
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
                'rsso-flush-ip-session': {
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
                'rsso-log-flags': {
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
                        'none',
                        'protocol-error',
                        'profile-missing',
                        'context-missing',
                        'accounting-stop-missed',
                        'accounting-event',
                        'radiusd-other',
                        'endpoint-block'
                    ]
                },
                'rsso-log-period': {
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
                'rsso-radius-response': {
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
                'rsso-radius-server-port': {
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
                'rsso-secret': {
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
                'rsso-validate-request-secret': {
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
                'secondary-secret': {
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
                'secondary-server': {
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
                'secret': {
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
                'server': {
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
                'source-ip': {
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
                'sso-attribute': {
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
                        'User-Name',
                        'User-Password',
                        'CHAP-Password',
                        'NAS-IP-Address',
                        'NAS-Port',
                        'Service-Type',
                        'Framed-Protocol',
                        'Framed-IP-Address',
                        'Framed-IP-Netmask',
                        'Framed-Routing',
                        'Filter-Id',
                        'Framed-MTU',
                        'Framed-Compression',
                        'Login-IP-Host',
                        'Login-Service',
                        'Login-TCP-Port',
                        'Reply-Message',
                        'Callback-Number',
                        'Callback-Id',
                        'Framed-Route',
                        'Framed-IPX-Network',
                        'State',
                        'Class',
                        'Session-Timeout',
                        'Idle-Timeout',
                        'Termination-Action',
                        'Called-Station-Id',
                        'Calling-Station-Id',
                        'NAS-Identifier',
                        'Proxy-State',
                        'Login-LAT-Service',
                        'Login-LAT-Node',
                        'Login-LAT-Group',
                        'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network',
                        'Framed-AppleTalk-Zone',
                        'Acct-Status-Type',
                        'Acct-Delay-Time',
                        'Acct-Input-Octets',
                        'Acct-Output-Octets',
                        'Acct-Session-Id',
                        'Acct-Authentic',
                        'Acct-Session-Time',
                        'Acct-Input-Packets',
                        'Acct-Output-Packets',
                        'Acct-Terminate-Cause',
                        'Acct-Multi-Session-Id',
                        'Acct-Link-Count',
                        'CHAP-Challenge',
                        'NAS-Port-Type',
                        'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'sso-attribute-key': {
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
                'sso-attribute-value-override': {
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
                'tertiary-secret': {
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
                'tertiary-server': {
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
                'timeout': {
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
                'use-group-for-profile': {
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
                'use-management-vdom': {
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
                'username-case-sensitive': {
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
                'interface': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'interface-select-method': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'auto',
                        'sdwan',
                        'specify'
                    ],
                    'type': 'str'
                },
                'group-override-attr-type': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'filter-Id',
                        'class'
                    ],
                    'type': 'str'
                },
                'switch-controller-acct-fast-framedip-detect': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'accounting-server': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'interface': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'interface-select-method': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'auto',
                                'sdwan',
                                'specify'
                            ],
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'secret': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'server': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'source-ip': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
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
                'switch-controller-service-type': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'login',
                        'framed',
                        'callback-login',
                        'callback-framed',
                        'outbound',
                        'administrative',
                        'nas-prompt',
                        'authenticate-only',
                        'callback-nas-prompt',
                        'call-check',
                        'callback-administrative'
                    ]
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_radius_dynamicmapping'),
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
