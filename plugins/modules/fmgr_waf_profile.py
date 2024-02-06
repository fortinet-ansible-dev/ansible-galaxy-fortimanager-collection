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
module: fmgr_waf_profile
short_description: Web application firewall configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    waf_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            extended-log:
                type: str
                description: Deprecated, please rename it to extended_log. Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            external:
                type: str
                description: Disable/Enable external HTTP Inspection.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: WAF Profile name.
                required: true
            url-access:
                type: list
                elements: dict
                description: Deprecated, please rename it to url_access. Url-Access.
                suboptions:
                    access-pattern:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to access_pattern. Access-Pattern.
                        suboptions:
                            id:
                                type: int
                                description: URL access pattern ID.
                            negate:
                                type: str
                                description: Enable/disable match negation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            srcaddr:
                                type: str
                                description: Source address.
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'bypass'
                            - 'permit'
                            - 'block'
                    address:
                        type: str
                        description: Host address.
                    id:
                        type: int
                        description: URL access ID.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
            address-list:
                type: dict
                description: Deprecated, please rename it to address_list.
                suboptions:
                    blocked-address:
                        type: raw
                        description: (list or str) Deprecated, please rename it to blocked_address. Blocked address.
                    blocked-log:
                        type: str
                        description: Deprecated, please rename it to blocked_log. Enable/disable logging on blocked addresses.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    trusted-address:
                        type: raw
                        description: (list or str) Deprecated, please rename it to trusted_address. Trusted address.
            constraint:
                type: dict
                description: No description.
                suboptions:
                    content-length:
                        type: dict
                        description: Deprecated, please rename it to content_length.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP content in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    exception:
                        type: list
                        elements: dict
                        description: Exception.
                        suboptions:
                            address:
                                type: str
                                description: Host address.
                            content-length:
                                type: str
                                description: Deprecated, please rename it to content_length. HTTP content length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            header-length:
                                type: str
                                description: Deprecated, please rename it to header_length. HTTP header length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            hostname:
                                type: str
                                description: Enable/disable hostname check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                                description: Exception ID.
                            line-length:
                                type: str
                                description: Deprecated, please rename it to line_length. HTTP line length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            malformed:
                                type: str
                                description: Enable/disable malformed HTTP request check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-cookie:
                                type: str
                                description: Deprecated, please rename it to max_cookie. Maximum number of cookies in HTTP request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-header-line:
                                type: str
                                description: Deprecated, please rename it to max_header_line. Maximum number of HTTP header line.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-range-segment:
                                type: str
                                description: Deprecated, please rename it to max_range_segment. Maximum number of range segments in HTTP range line.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-url-param:
                                type: str
                                description: Deprecated, please rename it to max_url_param. Maximum number of parameters in URL.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            method:
                                type: str
                                description: Enable/disable HTTP method check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            param-length:
                                type: str
                                description: Deprecated, please rename it to param_length. Maximum length of parameter in URL, HTTP POST request or HTT...
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            url-param-length:
                                type: str
                                description: Deprecated, please rename it to url_param_length. Maximum length of parameter in URL.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: Enable/disable HTTP version check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    header-length:
                        type: dict
                        description: Deprecated, please rename it to header_length.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP header in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    hostname:
                        type: dict
                        description: No description.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    line-length:
                        type: dict
                        description: Deprecated, please rename it to line_length.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP line in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    malformed:
                        type: dict
                        description: No description.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-cookie:
                        type: dict
                        description: Deprecated, please rename it to max_cookie.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-cookie:
                                type: int
                                description: Deprecated, please rename it to max_cookie. Maximum number of cookies in HTTP request
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-header-line:
                        type: dict
                        description: Deprecated, please rename it to max_header_line.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-header-line:
                                type: int
                                description: Deprecated, please rename it to max_header_line. Maximum number HTTP header lines
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-range-segment:
                        type: dict
                        description: Deprecated, please rename it to max_range_segment.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-range-segment:
                                type: int
                                description: Deprecated, please rename it to max_range_segment. Maximum number of range segments in HTTP range line
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-url-param:
                        type: dict
                        description: Deprecated, please rename it to max_url_param.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-url-param:
                                type: int
                                description: Deprecated, please rename it to max_url_param. Maximum number of parameters in URL
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    method:
                        type: dict
                        description: No description.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    param-length:
                        type: dict
                        description: Deprecated, please rename it to param_length.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    url-param-length:
                        type: dict
                        description: Deprecated, please rename it to url_param_length.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Maximum length of URL parameter in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    version:
                        type: dict
                        description: No description.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
            method:
                type: dict
                description: No description.
                suboptions:
                    default-allowed-methods:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to default_allowed_methods. Methods.
                        choices:
                            - 'delete'
                            - 'get'
                            - 'head'
                            - 'options'
                            - 'post'
                            - 'put'
                            - 'trace'
                            - 'others'
                            - 'connect'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    method-policy:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to method_policy. Method-Policy.
                        suboptions:
                            address:
                                type: str
                                description: Host address.
                            allowed-methods:
                                type: list
                                elements: str
                                description: Deprecated, please rename it to allowed_methods. Allowed Methods.
                                choices:
                                    - 'delete'
                                    - 'get'
                                    - 'head'
                                    - 'options'
                                    - 'post'
                                    - 'put'
                                    - 'trace'
                                    - 'others'
                                    - 'connect'
                            id:
                                type: int
                                description: HTTP method policy ID.
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
            signature:
                type: dict
                description: No description.
                suboptions:
                    credit-card-detection-threshold:
                        type: int
                        description: Deprecated, please rename it to credit_card_detection_threshold. The minimum number of Credit cards to detect viol...
                    custom-signature:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to custom_signature. Custom-Signature.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            case-sensitivity:
                                type: str
                                description: Deprecated, please rename it to case_sensitivity. Case sensitivity in pattern.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            direction:
                                type: str
                                description: Traffic direction.
                                choices:
                                    - 'request'
                                    - 'response'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            name:
                                type: str
                                description: Signature name.
                            pattern:
                                type: str
                                description: Match pattern.
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            target:
                                type: list
                                elements: str
                                description: Match HTTP target.
                                choices:
                                    - 'arg'
                                    - 'arg-name'
                                    - 'req-body'
                                    - 'req-cookie'
                                    - 'req-cookie-name'
                                    - 'req-filename'
                                    - 'req-header'
                                    - 'req-header-name'
                                    - 'req-raw-uri'
                                    - 'req-uri'
                                    - 'resp-body'
                                    - 'resp-hdr'
                                    - 'resp-status'
                    disabled-signature:
                        type: raw
                        description: (list or str) Deprecated, please rename it to disabled_signature. Disabled signatures
                    disabled-sub-class:
                        type: raw
                        description: (list or str) Deprecated, please rename it to disabled_sub_class. Disabled signature subclasses.
                    main-class:
                        type: dict
                        description: Deprecated, please rename it to main_class.
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            id:
                                type: int
                                description: Main signature class ID.
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Web application firewall configuration.
      fortinet.fortimanager.fmgr_waf_profile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        waf_profile:
          comment: <string>
          extended_log: <value in [disable, enable]>
          external: <value in [disable, enable]>
          name: <string>
          url_access:
            -
              access_pattern:
                -
                  id: <integer>
                  negate: <value in [disable, enable]>
                  pattern: <string>
                  regex: <value in [disable, enable]>
                  srcaddr: <string>
              action: <value in [bypass, permit, block]>
              address: <string>
              id: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
          address_list:
            blocked_address: <list or string>
            blocked_log: <value in [disable, enable]>
            severity: <value in [low, medium, high]>
            status: <value in [disable, enable]>
            trusted_address: <list or string>
          constraint:
            content_length:
              action: <value in [allow, block]>
              length: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            exception:
              -
                address: <string>
                content_length: <value in [disable, enable]>
                header_length: <value in [disable, enable]>
                hostname: <value in [disable, enable]>
                id: <integer>
                line_length: <value in [disable, enable]>
                malformed: <value in [disable, enable]>
                max_cookie: <value in [disable, enable]>
                max_header_line: <value in [disable, enable]>
                max_range_segment: <value in [disable, enable]>
                max_url_param: <value in [disable, enable]>
                method: <value in [disable, enable]>
                param_length: <value in [disable, enable]>
                pattern: <string>
                regex: <value in [disable, enable]>
                url_param_length: <value in [disable, enable]>
                version: <value in [disable, enable]>
            header_length:
              action: <value in [allow, block]>
              length: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            hostname:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            line_length:
              action: <value in [allow, block]>
              length: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            malformed:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            max_cookie:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              max_cookie: <integer>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            max_header_line:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              max_header_line: <integer>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            max_range_segment:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              max_range_segment: <integer>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            max_url_param:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              max_url_param: <integer>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            method:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            param_length:
              action: <value in [allow, block]>
              length: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            url_param_length:
              action: <value in [allow, block]>
              length: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
            version:
              action: <value in [allow, block]>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
          method:
            default_allowed_methods:
              - delete
              - get
              - head
              - options
              - post
              - put
              - trace
              - others
              - connect
            log: <value in [disable, enable]>
            method_policy:
              -
                address: <string>
                allowed_methods:
                  - delete
                  - get
                  - head
                  - options
                  - post
                  - put
                  - trace
                  - others
                  - connect
                id: <integer>
                pattern: <string>
                regex: <value in [disable, enable]>
            severity: <value in [low, medium, high]>
            status: <value in [disable, enable]>
          signature:
            credit_card_detection_threshold: <integer>
            custom_signature:
              -
                action: <value in [allow, block, erase]>
                case_sensitivity: <value in [disable, enable]>
                direction: <value in [request, response]>
                log: <value in [disable, enable]>
                name: <string>
                pattern: <string>
                severity: <value in [low, medium, high]>
                status: <value in [disable, enable]>
                target:
                  - arg
                  - arg-name
                  - req-body
                  - req-cookie
                  - req-cookie-name
                  - req-filename
                  - req-header
                  - req-header-name
                  - req-raw-uri
                  - req-uri
                  - resp-body
                  - resp-hdr
                  - resp-status
            disabled_signature: <list or string>
            disabled_sub_class: <list or string>
            main_class:
              action: <value in [allow, block, erase]>
              id: <integer>
              log: <value in [disable, enable]>
              severity: <value in [low, medium, high]>
              status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/waf/profile',
        '/pm/config/global/obj/waf/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
        '/pm/config/global/obj/waf/profile/{profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'waf_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'external': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'url-access': {
                    'type': 'list',
                    'options': {
                        'access-pattern': {
                            'type': 'list',
                            'options': {
                                'id': {'type': 'int'},
                                'negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                                'pattern': {'type': 'str'},
                                'regex': {'choices': ['disable', 'enable'], 'type': 'str'},
                                'srcaddr': {'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'action': {'choices': ['bypass', 'permit', 'block'], 'type': 'str'},
                        'address': {'type': 'str'},
                        'id': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'address-list': {
                    'type': 'dict',
                    'options': {
                        'blocked-address': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'},
                        'blocked-log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trusted-address': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'}
                    }
                },
                'constraint': {
                    'type': 'dict',
                    'options': {
                        'content-length': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'exception': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'address': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'content-length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'header-length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'hostname': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'line-length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'malformed': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-cookie': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-header-line': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-range-segment': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-url-param': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'method': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'param-length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'pattern': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'regex': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'url-param-length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'version': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'header-length': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'hostname': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'line-length': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'malformed': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'max-cookie': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-cookie': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'max-header-line': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-header-line': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'max-range-segment': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-range-segment': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'max-url-param': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-url-param': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'method': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'param-length': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'url-param-length': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'length': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'version': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        }
                    }
                },
                'method': {
                    'type': 'dict',
                    'options': {
                        'default-allowed-methods': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'others', 'connect'],
                            'elements': 'str'
                        },
                        'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'method-policy': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'address': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'allowed-methods': {
                                    'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                                    'type': 'list',
                                    'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'others', 'connect'],
                                    'elements': 'str'
                                },
                                'id': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'pattern': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'regex': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'signature': {
                    'type': 'dict',
                    'options': {
                        'credit-card-detection-threshold': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                        'custom-signature': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block', 'erase'], 'type': 'str'},
                                'case-sensitivity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'direction': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['request', 'response'], 'type': 'str'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'name': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'pattern': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'target': {
                                    'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                                    'type': 'list',
                                    'choices': [
                                        'arg', 'arg-name', 'req-body', 'req-cookie', 'req-cookie-name', 'req-filename', 'req-header', 'req-header-name',
                                        'req-raw-uri', 'req-uri', 'resp-body', 'resp-hdr', 'resp-status'
                                    ],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'disabled-signature': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'},
                        'disabled-sub-class': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'},
                        'main-class': {
                            'type': 'dict',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'block', 'erase'], 'type': 'str'},
                                'id': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'},
                                'log': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'severity': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                                'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        }
                    }
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile'),
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
