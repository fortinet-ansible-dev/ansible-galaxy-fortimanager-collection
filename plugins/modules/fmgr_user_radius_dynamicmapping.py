#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    radius:
        description: The parameter (radius) in requested url.
        type: str
        required: true
    user_radius_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            acct-all-servers:
                type: str
                description: Deprecated, please rename it to acct_all_servers.
                choices:
                    - 'disable'
                    - 'enable'
            acct-interim-interval:
                type: int
                description: Deprecated, please rename it to acct_interim_interval.
            all-usergroup:
                type: str
                description: Deprecated, please rename it to all_usergroup.
                choices:
                    - 'disable'
                    - 'enable'
            auth-type:
                type: str
                description: Deprecated, please rename it to auth_type.
                choices:
                    - 'pap'
                    - 'chap'
                    - 'ms_chap'
                    - 'ms_chap_v2'
                    - 'auto'
            class:
                type: raw
                description: (list) No description.
            dp-carrier-endpoint-attribute:
                type: str
                description: Deprecated, please rename it to dp_carrier_endpoint_attribute.
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
                description: Deprecated, please rename it to dp_carrier_endpoint_block_attribute.
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
                description: Deprecated, please rename it to dp_context_timeout.
            dp-flush-ip-session:
                type: str
                description: Deprecated, please rename it to dp_flush_ip_session.
                choices:
                    - 'disable'
                    - 'enable'
            dp-hold-time:
                type: int
                description: Deprecated, please rename it to dp_hold_time.
            dp-http-header:
                type: str
                description: Deprecated, please rename it to dp_http_header.
            dp-http-header-fallback:
                type: str
                description: Deprecated, please rename it to dp_http_header_fallback.
                choices:
                    - 'ip-header-address'
                    - 'default-profile'
            dp-http-header-status:
                type: str
                description: Deprecated, please rename it to dp_http_header_status.
                choices:
                    - 'disable'
                    - 'enable'
            dp-http-header-suppress:
                type: str
                description: Deprecated, please rename it to dp_http_header_suppress.
                choices:
                    - 'disable'
                    - 'enable'
            dp-log-dyn_flags:
                type: list
                elements: str
                description: Deprecated, please rename it to dp_log_dyn_flags.
                choices:
                    - 'none'
                    - 'protocol-error'
                    - 'profile-missing'
                    - 'context-missing'
                    - 'accounting-stop-missed'
                    - 'accounting-event'
                    - 'radiusd-other'
                    - 'endpoint-block'
            dp-log-period:
                type: int
                description: Deprecated, please rename it to dp_log_period.
            dp-mem-percent:
                type: int
                description: Deprecated, please rename it to dp_mem_percent.
            dp-profile-attribute:
                type: str
                description: Deprecated, please rename it to dp_profile_attribute.
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
                description: Deprecated, please rename it to dp_profile_attribute_key.
            dp-radius-response:
                type: str
                description: Deprecated, please rename it to dp_radius_response.
                choices:
                    - 'disable'
                    - 'enable'
            dp-radius-server-port:
                type: int
                description: Deprecated, please rename it to dp_radius_server_port.
            dp-secret:
                type: raw
                description: (list) Deprecated, please rename it to dp_secret.
            dp-validate-request-secret:
                type: str
                description: Deprecated, please rename it to dp_validate_request_secret.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile:
                type: str
                description: Deprecated, please rename it to dynamic_profile.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-translation:
                type: str
                description: Deprecated, please rename it to endpoint_translation.
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-convert-hex:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_convert_hex.
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-header:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_header.
            ep-carrier-endpoint-header-suppress:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_header_suppress.
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-prefix:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_prefix.
                choices:
                    - 'disable'
                    - 'enable'
            ep-carrier-endpoint-prefix-range-max:
                type: int
                description: Deprecated, please rename it to ep_carrier_endpoint_prefix_range_max.
            ep-carrier-endpoint-prefix-range-min:
                type: int
                description: Deprecated, please rename it to ep_carrier_endpoint_prefix_range_min.
            ep-carrier-endpoint-prefix-string:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_prefix_string.
            ep-carrier-endpoint-source:
                type: str
                description: Deprecated, please rename it to ep_carrier_endpoint_source.
                choices:
                    - 'http-header'
                    - 'cookie'
            ep-ip-header:
                type: str
                description: Deprecated, please rename it to ep_ip_header.
            ep-ip-header-suppress:
                type: str
                description: Deprecated, please rename it to ep_ip_header_suppress.
                choices:
                    - 'disable'
                    - 'enable'
            ep-missing-header-fallback:
                type: str
                description: Deprecated, please rename it to ep_missing_header_fallback.
                choices:
                    - 'session-ip'
                    - 'policy-profile'
            ep-profile-query-type:
                type: str
                description: Deprecated, please rename it to ep_profile_query_type.
                choices:
                    - 'session-ip'
                    - 'extract-ip'
                    - 'extract-carrier-endpoint'
            h3c-compatibility:
                type: str
                description: Deprecated, please rename it to h3c_compatibility.
                choices:
                    - 'disable'
                    - 'enable'
            nas-ip:
                type: str
                description: Deprecated, please rename it to nas_ip.
            password-encoding:
                type: str
                description: Deprecated, please rename it to password_encoding.
                choices:
                    - 'ISO-8859-1'
                    - 'auto'
            password-renewal:
                type: str
                description: Deprecated, please rename it to password_renewal.
                choices:
                    - 'disable'
                    - 'enable'
            radius-coa:
                type: str
                description: Deprecated, please rename it to radius_coa.
                choices:
                    - 'disable'
                    - 'enable'
            radius-port:
                type: int
                description: Deprecated, please rename it to radius_port.
            rsso:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            rsso-context-timeout:
                type: int
                description: Deprecated, please rename it to rsso_context_timeout.
            rsso-endpoint-attribute:
                type: str
                description: Deprecated, please rename it to rsso_endpoint_attribute.
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
                description: Deprecated, please rename it to rsso_endpoint_block_attribute.
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
                description: Deprecated, please rename it to rsso_ep_one_ip_only.
                choices:
                    - 'disable'
                    - 'enable'
            rsso-flush-ip-session:
                type: str
                description: Deprecated, please rename it to rsso_flush_ip_session.
                choices:
                    - 'disable'
                    - 'enable'
            rsso-log-flags:
                type: list
                elements: str
                description: Deprecated, please rename it to rsso_log_flags.
                choices:
                    - 'none'
                    - 'protocol-error'
                    - 'profile-missing'
                    - 'context-missing'
                    - 'accounting-stop-missed'
                    - 'accounting-event'
                    - 'radiusd-other'
                    - 'endpoint-block'
            rsso-log-period:
                type: int
                description: Deprecated, please rename it to rsso_log_period.
            rsso-radius-response:
                type: str
                description: Deprecated, please rename it to rsso_radius_response.
                choices:
                    - 'disable'
                    - 'enable'
            rsso-radius-server-port:
                type: int
                description: Deprecated, please rename it to rsso_radius_server_port.
            rsso-secret:
                type: raw
                description: (list) Deprecated, please rename it to rsso_secret.
            rsso-validate-request-secret:
                type: str
                description: Deprecated, please rename it to rsso_validate_request_secret.
                choices:
                    - 'disable'
                    - 'enable'
            secondary-secret:
                type: raw
                description: (list) Deprecated, please rename it to secondary_secret.
            secondary-server:
                type: str
                description: Deprecated, please rename it to secondary_server.
            secret:
                type: raw
                description: (list) No description.
            server:
                type: str
                description: No description.
            source-ip:
                type: str
                description: Deprecated, please rename it to source_ip.
            sso-attribute:
                type: str
                description: Deprecated, please rename it to sso_attribute.
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
                description: Deprecated, please rename it to sso_attribute_key.
            sso-attribute-value-override:
                type: str
                description: Deprecated, please rename it to sso_attribute_value_override.
                choices:
                    - 'disable'
                    - 'enable'
            tertiary-secret:
                type: raw
                description: (list) Deprecated, please rename it to tertiary_secret.
            tertiary-server:
                type: str
                description: Deprecated, please rename it to tertiary_server.
            timeout:
                type: int
                description: No description.
            use-group-for-profile:
                type: str
                description: Deprecated, please rename it to use_group_for_profile.
                choices:
                    - 'disable'
                    - 'enable'
            use-management-vdom:
                type: str
                description: Deprecated, please rename it to use_management_vdom.
                choices:
                    - 'disable'
                    - 'enable'
            username-case-sensitive:
                type: str
                description: Deprecated, please rename it to username_case_sensitive.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: str
                description: No description.
            interface-select-method:
                type: str
                description: Deprecated, please rename it to interface_select_method.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            group-override-attr-type:
                type: str
                description: Deprecated, please rename it to group_override_attr_type.
                choices:
                    - 'filter-Id'
                    - 'class'
            switch-controller-acct-fast-framedip-detect:
                type: int
                description: Deprecated, please rename it to switch_controller_acct_fast_framedip_detect.
            accounting-server:
                type: list
                elements: dict
                description: Deprecated, please rename it to accounting_server.
                suboptions:
                    id:
                        type: int
                        description: No description.
                    interface:
                        type: str
                        description: No description.
                    interface-select-method:
                        type: str
                        description: Deprecated, please rename it to interface_select_method.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    port:
                        type: int
                        description: No description.
                    secret:
                        type: raw
                        description: (list) No description.
                    server:
                        type: str
                        description: No description.
                    source-ip:
                        type: str
                        description: Deprecated, please rename it to source_ip.
                    status:
                        type: str
                        description: No description.
                        choices:
                            - 'disable'
                            - 'enable'
            switch-controller-service-type:
                type: list
                elements: str
                description: Deprecated, please rename it to switch_controller_service_type.
                choices:
                    - 'login'
                    - 'framed'
                    - 'callback-login'
                    - 'callback-framed'
                    - 'outbound'
                    - 'administrative'
                    - 'nas-prompt'
                    - 'authenticate-only'
                    - 'callback-nas-prompt'
                    - 'call-check'
                    - 'callback-administrative'
            delimiter:
                type: str
                description: Configure delimiter to be used for separating profile group names in the SSO attribute
                choices:
                    - 'plus'
                    - 'comma'
            mac-case:
                type: str
                description: Deprecated, please rename it to mac_case. MAC authentication case
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac-password-delimiter:
                type: str
                description: Deprecated, please rename it to mac_password_delimiter. MAC authentication password delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac-username-delimiter:
                type: str
                description: Deprecated, please rename it to mac_username_delimiter. MAC authentication username delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            nas-id:
                type: str
                description: Deprecated, please rename it to nas_id. Custom NAS identifier.
            nas-id-type:
                type: str
                description: Deprecated, please rename it to nas_id_type. NAS identifier type configuration
                choices:
                    - 'legacy'
                    - 'custom'
                    - 'hostname'
            ca-cert:
                type: str
                description: Deprecated, please rename it to ca_cert. CA of server to trust under TLS.
            client-cert:
                type: str
                description: Deprecated, please rename it to client_cert. Client certificate to use under TLS.
            server-identity-check:
                type: str
                description: Deprecated, please rename it to server_identity_check. Enable/disable RADIUS server identity check
                choices:
                    - 'disable'
                    - 'enable'
            status-ttl:
                type: int
                description: Deprecated, please rename it to status_ttl. Time for which server reachability is cached so that when a server is unreacha...
            tls-min-proto-version:
                type: str
                description: Deprecated, please rename it to tls_min_proto_version. Minimum supported protocol version for TLS connections
                choices:
                    - 'default'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            transport-protocol:
                type: str
                description: Deprecated, please rename it to transport_protocol. Transport protocol to be used
                choices:
                    - 'udp'
                    - 'tcp'
                    - 'tls'
            account-key-cert-field:
                type: str
                description: Deprecated, please rename it to account_key_cert_field. Define subject identity field in certificate for user access right...
                choices:
                    - 'othername'
                    - 'rfc822name'
                    - 'dnsname'
            account-key-processing:
                type: str
                description: Deprecated, please rename it to account_key_processing. Account key processing operation.
                choices:
                    - 'same'
                    - 'strip'
            call-station-id-type:
                type: str
                description: Deprecated, please rename it to call_station_id_type. Calling & Called station identifier type configuration
                choices:
                    - 'legacy'
                    - 'IP'
                    - 'MAC'
            switch-controller-nas-ip-dynamic:
                type: str
                description: Deprecated, please rename it to switch_controller_nas_ip_dynamic. Enable/Disable switch-controller nas-ip dynamic to dynam...
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure dynamic mappings of RADIUS server
      fortinet.fortimanager.fmgr_user_radius_dynamicmapping:
        bypass_validation: false
        adom: ansible
        radius: ansible-test-radius # name
        state: present
        user_radius_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          server: ansible
          timeout: 100

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of RADIUS server
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_radius_dynamicmapping"
          params:
            adom: "ansible"
            radius: "ansible-test-radius" # name
            dynamic_mapping: "your_value"
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


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
        'adom': {'required': True, 'type': 'str'},
        'radius': {'required': True, 'type': 'str'},
        'user_radius_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'acct-all-servers': {'choices': ['disable', 'enable'], 'type': 'str'},
                'acct-interim-interval': {'type': 'int'},
                'all-usergroup': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-type': {'choices': ['pap', 'chap', 'ms_chap', 'ms_chap_v2', 'auto'], 'type': 'str'},
                'class': {'type': 'raw'},
                'dp-carrier-endpoint-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id',
                        'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                        'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time',
                        'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets',
                        'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type',
                        'Port-Limit', 'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-carrier-endpoint-block-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id',
                        'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                        'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time',
                        'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets',
                        'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type',
                        'Port-Limit', 'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-context-timeout': {'type': 'int'},
                'dp-flush-ip-session': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-hold-time': {'type': 'int'},
                'dp-http-header': {'type': 'str'},
                'dp-http-header-fallback': {'choices': ['ip-header-address', 'default-profile'], 'type': 'str'},
                'dp-http-header-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-http-header-suppress': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-log-dyn_flags': {
                    'type': 'list',
                    'choices': [
                        'none', 'protocol-error', 'profile-missing', 'context-missing', 'accounting-stop-missed', 'accounting-event', 'radiusd-other',
                        'endpoint-block'
                    ],
                    'elements': 'str'
                },
                'dp-log-period': {'type': 'int'},
                'dp-mem-percent': {'type': 'int'},
                'dp-profile-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id',
                        'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                        'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time',
                        'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets',
                        'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type',
                        'Port-Limit', 'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'dp-profile-attribute-key': {'no_log': True, 'type': 'str'},
                'dp-radius-response': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-radius-server-port': {'type': 'int'},
                'dp-secret': {'no_log': True, 'type': 'raw'},
                'dp-validate-request-secret': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic-profile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'endpoint-translation': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ep-carrier-endpoint-convert-hex': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ep-carrier-endpoint-header': {'type': 'str'},
                'ep-carrier-endpoint-header-suppress': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ep-carrier-endpoint-prefix': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ep-carrier-endpoint-prefix-range-max': {'type': 'int'},
                'ep-carrier-endpoint-prefix-range-min': {'type': 'int'},
                'ep-carrier-endpoint-prefix-string': {'type': 'str'},
                'ep-carrier-endpoint-source': {'choices': ['http-header', 'cookie'], 'type': 'str'},
                'ep-ip-header': {'type': 'str'},
                'ep-ip-header-suppress': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ep-missing-header-fallback': {'choices': ['session-ip', 'policy-profile'], 'type': 'str'},
                'ep-profile-query-type': {'choices': ['session-ip', 'extract-ip', 'extract-carrier-endpoint'], 'type': 'str'},
                'h3c-compatibility': {'choices': ['disable', 'enable'], 'type': 'str'},
                'nas-ip': {'type': 'str'},
                'password-encoding': {'choices': ['ISO-8859-1', 'auto'], 'type': 'str'},
                'password-renewal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-coa': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-port': {'type': 'int'},
                'rsso': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-context-timeout': {'type': 'int'},
                'rsso-endpoint-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time', 'Acct-Input-Octets',
                        'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets', 'Acct-Output-Packets',
                        'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'rsso-endpoint-block-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time', 'Acct-Input-Octets',
                        'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets', 'Acct-Output-Packets',
                        'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'rsso-ep-one-ip-only': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-flush-ip-session': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-log-flags': {
                    'type': 'list',
                    'choices': [
                        'none', 'protocol-error', 'profile-missing', 'context-missing', 'accounting-stop-missed', 'accounting-event', 'radiusd-other',
                        'endpoint-block'
                    ],
                    'elements': 'str'
                },
                'rsso-log-period': {'type': 'int'},
                'rsso-radius-response': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-radius-server-port': {'type': 'int'},
                'rsso-secret': {'no_log': True, 'type': 'raw'},
                'rsso-validate-request-secret': {'choices': ['disable', 'enable'], 'type': 'str'},
                'secondary-secret': {'no_log': True, 'type': 'raw'},
                'secondary-server': {'type': 'str'},
                'secret': {'no_log': True, 'type': 'raw'},
                'server': {'type': 'str'},
                'source-ip': {'type': 'str'},
                'sso-attribute': {
                    'choices': [
                        'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                        'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression', 'Login-IP-Host',
                        'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network',
                        'State', 'Class', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Link',
                        'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type', 'Acct-Delay-Time', 'Acct-Input-Octets',
                        'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time', 'Acct-Input-Packets', 'Acct-Output-Packets',
                        'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count', 'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit',
                        'Login-LAT-Port'
                    ],
                    'type': 'str'
                },
                'sso-attribute-key': {'no_log': True, 'type': 'str'},
                'sso-attribute-value-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tertiary-secret': {'no_log': True, 'type': 'raw'},
                'tertiary-server': {'type': 'str'},
                'timeout': {'type': 'int'},
                'use-group-for-profile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'use-management-vdom': {'choices': ['disable', 'enable'], 'type': 'str'},
                'username-case-sensitive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.2.5', '6.2.12'], ['6.4.1', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'group-override-attr-type': {'v_range': [['6.4.0', '']], 'choices': ['filter-Id', 'class'], 'type': 'str'},
                'switch-controller-acct-fast-framedip-detect': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'accounting-server': {
                    'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                        'interface': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                        'interface-select-method': {
                            'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'int'},
                        'secret': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'server': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                        'source-ip': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'type': 'str'},
                        'status': {'v_range': [['6.2.6', '6.2.12'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'switch-controller-service-type': {
                    'v_range': [['6.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'login', 'framed', 'callback-login', 'callback-framed', 'outbound', 'administrative', 'nas-prompt', 'authenticate-only',
                        'callback-nas-prompt', 'call-check', 'callback-administrative'
                    ],
                    'elements': 'str'
                },
                'delimiter': {'v_range': [['7.2.0', '']], 'choices': ['plus', 'comma'], 'type': 'str'},
                'mac-case': {'v_range': [['7.2.1', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {'v_range': [['7.2.1', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-username-delimiter': {'v_range': [['7.2.1', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'nas-id': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'nas-id-type': {'v_range': [['7.2.2', '']], 'choices': ['legacy', 'custom', 'hostname'], 'type': 'str'},
                'ca-cert': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'server-identity-check': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status-ttl': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'tls-min-proto-version': {
                    'v_range': [['7.4.0', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'transport-protocol': {'v_range': [['7.4.0', '']], 'choices': ['udp', 'tcp', 'tls'], 'type': 'str'},
                'account-key-cert-field': {'v_range': [['7.4.1', '']], 'choices': ['othername', 'rfc822name', 'dnsname'], 'type': 'str'},
                'account-key-processing': {'v_range': [['7.4.1', '']], 'choices': ['same', 'strip'], 'type': 'str'},
                'call-station-id-type': {'v_range': [['7.4.1', '']], 'choices': ['legacy', 'IP', 'MAC'], 'type': 'str'},
                'switch-controller-nas-ip-dynamic': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_radius_dynamicmapping'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
